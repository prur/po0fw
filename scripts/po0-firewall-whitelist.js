/*
 * po0 防火墙自动加白
 * 兼容：Surge / Stash / Shadowrocket / Loon / Quantumult X
 * （Egern 运行模型不同，用独立的 egern/po0-firewall-whitelist.js）
 *
 * GET /api/firewall/<token> 只读查询当前来源 IP 与白名单；仅在当前 /24 尚未加白时，
 * POST /api/firewall/<token>/add 才执行写入。响应结构应为
 *   {enabled, whitelist:[{ip,slot}], limit, currentIp}。token 走 URL 路径，无需
 *   Authorization 头。服务端对已在白名单的 IP 做幂等处理（重复请求不
 *   重复占坑、不推进淘汰队列）。
 * 加白粒度为 C 段（/24）：服务端把 whitelist 条目和 currentIp 都归一化成
 *   x.x.x.0/24 回显；同段内换 IP 不产生新写入。脚本用 sameC24() 做匹配，
 *   兼容精确 IP 与 /24 段混杂的新旧格式。
 * 白名单写满后按写入时间先进先出自动淘汰最旧 IP；API 无删除接口。
 *
 * 策略：
 * - 所有自动任务先 GET；只有当前来源 /24 缺失时才 POST，避免重复写入撞限频。
 * - network-changed / engine-started 先用无 CAS 持久化存储做 60 秒 best-effort 所有者租约，
 *   并等待 100ms 复读确认写入胜者；服务端幂等与 GET-first 仍是并发下的最终防线。
 *   获胜会话再按 3s、5s、8s 的间隔确认三次，覆盖双 SIM 切换期间
 *   IPv6-only / 旧出口 / 新出口三个阶段。
 * - 事件路径单次 GET/POST 最多等 5 秒且不做嵌套重试，GET+POST 的最坏总运行
 *   约 46.1 秒，保持在模块 timeout=60 的预算内；cron / button 单次最多 7 秒并保留
 *   三次瞬时错误重试，GET+POST 的最坏总运行 51 秒；auto-interval 只发一次 GET。
 * - 面板 auto-interval 只做 GET；button 先 GET，缺失时才 POST，因此查看状态不会写白名单。
 * - 默认 slotless 写入：新 /24 在满额时按 FIFO 淘汰最旧普通记录；重复 /24
 *   服务端幂等，不重复占坑，也不推进淘汰队列。
 * - 可选固定槽位：token 后加 @N（如 pgnfw_xxx@0）→ POST .../add?slot=N，
 *   把本机 IP 钉在槽位 N，**永不被 LRU 淘汰**。槽位写入语义：
 *     · 本机 IP 已在该槽位 → 刷新 updated_at；
 *     · 槽位有旧 IP → 行级顶替，旧 IP 丢弃；
 *     · 本机 IP 已 slotless → 删 slotless 行升级到该槽位；
 *     · 本机 IP 已占用**别的**槽位 → 403 冲突，需先去 UI 删旧槽位（脚本会报 ❌）。
 * - 蜂窝（主接口 pdp_ip*）写入的 IP 仅做 📶 标记，便于面板识别。
 *
 * token 来源（优先级从高到低）：
 * 1. argument: tokens=<pgnfw_xxx>[@槽位],<pgnfw_yyy>（Surge/Loon/Stash 模块参数）
 * 2. 持久化存储 key "po0fw_tokens"（Quantumult X 等不支持参数的客户端，
 *    可用 BoxJs 或一次性脚本写入）
 * 3. 下面的 INLINE_TOKENS 常量（自己维护脚本副本时直接填这里）
 */

var INLINE_TOKENS = "";

var API_BASE = "https://124.221.69.228/api/firewall/"; // + <token> [+ "/add"]
var STORE_PREFIX = "po0_fw_";
var TOKENS_KEY = "po0fw_tokens";
var LAST_SUCCESS_KEY = "po0_fw_last_auto_success";
var EVENT_LEASE_KEY = "po0_fw_event_lease";
var EVENT_COALESCE_MS = 60000;
var EVENT_LEASE_SETTLE_MS = 100;
var HIST_WINDOW_MS = 24 * 3600 * 1000; // 📶 标记的记账窗口

/* ---------- 环境兼容层 ---------- */

var isQX = typeof $task !== "undefined";
var isSurgeLike = typeof $httpClient !== "undefined"; // Surge/Stash/Shadowrocket/Loon

// 客户端细分：各家注入的标识不同，Loon 有全局 $loon，
// Surge 系则在 $environment 里带 surge-version / shadowrocket-version 等字段。
var envInfo = "";
try {
  if (typeof $environment !== "undefined" && $environment) {
    envInfo = JSON.stringify($environment).toLowerCase();
  }
} catch (e) {}

var isLoon = typeof $loon !== "undefined" || envInfo.indexOf("loon") >= 0;
var isSurgeFamily =
  envInfo.indexOf("surge-version") >= 0 ||
  envInfo.indexOf("shadowrocket") >= 0 ||
  envInfo.indexOf("stash") >= 0;

// ⚠️ timeout 单位在不同客户端不一致：
//   Surge / Shadowrocket / Stash → 秒
//   Loon / Quantumult X          → 毫秒
// 写死 15 会让 Loon 只等 15 毫秒 → 必然超时 → 回调 error=null → 通知里显示 "(null)"。
// 无法判定时干脆不传 timeout，交给模块声明的 timeout=60 兜底，避免再踩单位坑。
var REQUEST_TIMEOUT = null;
if (isLoon || isQX) REQUEST_TIMEOUT = 15000;
else if (isSurgeFamily) REQUEST_TIMEOUT = 15;

function timeoutValue(seconds) {
  if (isLoon || isQX) return seconds * 1000;
  if (isSurgeFamily) return seconds;
  return null;
}

function storeRead(key) {
  if (isQX) return $prefs.valueForKey(key);
  if (typeof $persistentStore !== "undefined") return $persistentStore.read(key);
  return null;
}

function storeWrite(value, key) {
  if (isQX) return $prefs.setValueForKey(value, key);
  if (typeof $persistentStore !== "undefined") return $persistentStore.write(value, key);
  return false;
}

function notify(title, subtitle, body) {
  if (isQX) $notify(title, subtitle, body);
  else if (typeof $notification !== "undefined") $notification.post(title, subtitle, body);
}

// 各客户端失败时回传的 error 五花八门：Loon 在网络瞬断 / TLS 握手失败时
// 直接回调 error=null，裸 String(null) 只会得到毫无信息量的 "null"。
function describeHttpError(error) {
  var text;
  if (error === null || error === undefined) text = "";
  else if (typeof error === "object")
    text = String(error.message || error.error || error.description || "");
  else text = String(error);
  text = text.replace(/^\s+|\s+$/g, "");
  if (text === "" || text === "null" || text === "undefined" || text === "{}") {
    return "网络请求失败（超时 / 握手失败 / 被拦截）";
  }
  return sanitizeLogText(text);
}

function getHttpStatus(response) {
  if (!response || typeof response !== "object") return null;
  var raw = response.status !== undefined ? response.status : response.statusCode;
  var status = Number(raw);
  if (!isFinite(status) || Math.floor(status) !== status || status < 100 || status > 599) return null;
  return status;
}

function httpRequestOnce(method, opts) {
  return new Promise(function (resolve) {
    if (isQX) {
      opts.method = method;
      $task.fetch(opts).then(
        function (resp) {
          var status = getHttpStatus(resp);
          if (status === null) resolve({ error: "HTTP 响应缺少有效状态码" });
          else resolve({ body: resp.body, status: status });
        },
        function (err) {
          resolve({ error: describeHttpError((err && err.error) || err) });
        }
      );
    } else if (isSurgeLike) {
      // 注意：不能把 $httpClient.post 解引用成局部变量再调用 —— Shadowrocket 的
      // $httpClient 是 ObjC 桥接对象，脱离对象调用会抛
      // "self type check failed for Objective-C instance method"。必须直调。
      var cb = function (error, response, body) {
        if (error) resolve({ error: describeHttpError(error) });
        else {
          var status = getHttpStatus(response);
          if (status === null) resolve({ error: "HTTP 响应缺少有效状态码" });
          else resolve({ body: body, status: status });
        }
      };
      if (method === "POST") $httpClient.post(opts, cb);
      else $httpClient.get(opts, cb);
    } else {
      resolve({ error: "unsupported client" });
    }
  });
}

function delay(ms) {
  return new Promise(function (resolve) {
    if (typeof setTimeout === "function") setTimeout(resolve, ms);
    else resolve();
  });
}

// 移动网络下单次请求失败很常见（cron 触发时链路刚唤醒 / 切网瞬间）。
// 服务端对重复 IP 幂等，重试 POST /add 不会重复占坑或推进淘汰队列，因此可安全重试。
var HTTP_RETRY = 3;
var HTTP_RETRY_DELAY_MS = 1500;

// 服务端瞬时异常也值得重试：po0 API 偶发返回裸 400（body 仅 "Error"）/ 5xx，
// 几秒后同一 token 即成功。规范 JSON 错误（如 token 无效 {"code":400,...}）不重试。
function isRetryableServerError(r) {
  if (!r || !r.status) return false;
  if (r.status === 408 || r.status === 425 || r.status === 429 || r.status >= 500) return true;
  if (r.status >= 200 && r.status < 300) {
    try {
      var successBody = JSON.parse(r.body);
      var embeddedCode = Number(successBody && successBody.code);
      if (embeddedCode === 408 || embeddedCode === 425 || embeddedCode === 429 || embeddedCode >= 500) return true;
    } catch (e) {}
    return false;
  }
  if (r.status === 403) return false; // 槽位冲突，重试无意义
  try {
    JSON.parse(r.body);
    return false; // 其它规范 JSON 错误 = 确定性失败，不重试
  } catch (e) {
    return true; // 非 JSON body（如裸 "Error"）= 服务端瞬时异常
  }
}

function httpRequest(method, opts, attempt, maxAttempts) {
  attempt = attempt || 1;
  maxAttempts = maxAttempts || HTTP_RETRY;
  return httpRequestOnce(method, opts).then(function (r) {
    if (!r.error && !isRetryableServerError(r)) return r;
    if (attempt >= maxAttempts) {
      if (r.error && maxAttempts > 1) r.error = r.error + "（已重试 " + maxAttempts + " 次）";
      return r;
    }
    return delay(HTTP_RETRY_DELAY_MS * attempt).then(function () {
      return httpRequest(method, opts, attempt + 1, maxAttempts);
    });
  });
}

function getArgumentTokens() {
  if (typeof $argument === "undefined" || $argument === null) return "";
  // Loon 插件 argument=[{tokens}] 会注入对象形态
  if (typeof $argument === "object") return String($argument.tokens || "");
  if (typeof $argument === "string" && $argument.length > 0) {
    // Shadowrocket 等客户端可能把配置里的外层引号原样传入，先剥掉
    if (/^["'].*["']$/.test($argument)) $argument = $argument.slice(1, -1);
    // Loon 也可能注入 JSON 字符串
    if ($argument.charAt(0) === "{") {
      try {
        return String(JSON.parse($argument).tokens || "");
      } catch (e) {}
    }
    // Surge/Stash 风格 tokens=xxx&...
    var pairs = $argument.split("&");
    for (var i = 0; i < pairs.length; i++) {
      var idx = pairs[i].indexOf("=");
      if (idx > 0 && pairs[i].slice(0, idx) === "tokens") {
        return decodeURIComponent(pairs[i].slice(idx + 1));
      }
    }
    // 直接把整串当 token 填的兜底（如 Loon argument="pgnfw_..."）
    if ($argument.indexOf("pgnfw_") === 0) return $argument;
  }
  return "";
}

function onCellular() {
  try {
    var iface =
      ($network.v4 && $network.v4.primaryInterface) ||
      ($network.v6 && $network.v6.primaryInterface) ||
      "";
    return iface.indexOf("pdp_ip") === 0;
  } catch (e) {
    return false; // 客户端不支持 $network 时按非蜂窝处理
  }
}

function getTriggerName() {
  try {
    if (typeof $event !== "undefined" && $event && $event.name) return String($event.name);
  } catch (e) {}
  if (typeof $cronexp !== "undefined") return "cron";
  if (typeof $trigger !== "undefined" && $trigger) return String($trigger);
  try {
    if (typeof $script !== "undefined" && $script) {
      var scriptType = String($script.type || "").toLowerCase();
      var scriptName = String($script.name || "").toLowerCase();
      if (scriptType === "cron" || scriptName.indexOf("cron") >= 0) return "cron";
    }
  } catch (e) {}
  // Quantumult X 的 task_local 不提供 Surge 风格 $cronexp；本脚本在 QX 仅作为定时任务使用。
  if (isQX) return "cron";
  return "manual";
}

function isAutomaticTrigger(name) {
  return name === "network-changed" || name === "engine-started" || name === "cron";
}

function readEventLease() {
  var raw = storeRead(EVENT_LEASE_KEY) || "";
  try {
    var parsed = JSON.parse(raw);
    if (typeof parsed === "number") return { ts: parsed, owner: "legacy" };
    if (parsed && typeof parsed.ts === "number") {
      return { ts: parsed.ts, owner: String(parsed.owner || "") };
    }
  } catch (e) {}
  var legacy = parseInt(raw || "0", 10) || 0;
  return { ts: legacy, owner: legacy > 0 ? "legacy" : "" };
}

function prepareEventLease(name) {
  if (name !== "network-changed" && name !== "engine-started") {
    return Promise.resolve({ coalesced: false, owner: "", unavailable: false });
  }

  var now = Date.now();
  var previous = readEventLease();
  if (previous.ts > 0 && now - previous.ts >= 0 && now - previous.ts < EVENT_COALESCE_MS) {
    return Promise.resolve({ coalesced: true, owner: "", unavailable: false });
  }

  var owner = "event-" + now + "-" + Math.random().toString(36).slice(2, 10);
  try {
    if (typeof $script !== "undefined" && $script && $script.sessionID) owner = String($script.sessionID);
  } catch (e) {}

  var wrote = storeWrite(JSON.stringify({ ts: now, owner: owner }), EVENT_LEASE_KEY);
  if (!wrote) {
    if (typeof console !== "undefined" && typeof console.log === "function") {
      console.log("[po0fw] trigger=" + name + " lease=unavailable action=fail-open");
    }
    return Promise.resolve({ coalesced: false, owner: "", unavailable: true });
  }

  // 持久化存储没有 CAS；短暂让并发会话完成写入，再由最后保留的 owner 胜出。
  return delay(EVENT_LEASE_SETTLE_MS).then(function () {
    var confirmed = readEventLease();
    if (confirmed.owner !== owner) return { coalesced: true, owner: "", unavailable: false };
    return { coalesced: false, owner: owner, unavailable: false };
  });
}

function releaseEventLease(lease) {
  if (!lease || !lease.owner) return;
  try {
    var current = JSON.parse(storeRead(EVENT_LEASE_KEY) || "null");
    if (current && current.owner === lease.owner) storeWrite("0", EVENT_LEASE_KEY);
  } catch (e) {}
}

function getPrimaryInterface() {
  try {
    return (
      ($network.v4 && $network.v4.primaryInterface) ||
      ($network.v6 && $network.v6.primaryInterface) ||
      "unknown"
    );
  } catch (e) {
    return "unknown";
  }
}

function sanitizeLogText(value) {
  return String(value || "")
    .replace(/pgnfw_[A-Za-z0-9_-]+/g, "pgnfw_REDACTED")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 160);
}

function logRound(results, attempt, total, startedAt) {
  if (typeof console === "undefined" || typeof console.log !== "function") return;
  var details = results
    .map(function (ctx, index) {
      var st = ctx.st || {};
      var status = st.ready ? "ok" : st.error ? "error" : "not-applied";
      var diagnostic = "";
      if (st.httpStatus !== undefined && st.httpStatus !== null) diagnostic += " httpStatus=" + st.httpStatus;
      if (st.apiCode !== undefined && st.apiCode !== null) diagnostic += " apiCode=" + st.apiCode;
      if (st.error) diagnostic += " error=" + sanitizeLogText(st.error);
      return (
        "token#" +
        (index + 1) +
        " status=" +
        status +
        " currentIp=" +
        (st.currentIp || "unknown") +
        diagnostic
      );
    })
    .join(" ");
  console.log(
    "[po0fw] trigger=" +
      triggerName +
      " attempt=" +
      attempt +
      "/" +
      total +
      " interface=" +
      getPrimaryInterface() +
      " latencyMs=" +
      Math.max(0, Date.now() - startedAt) +
      " " +
      details
  );
}

function finish(title, content, allOk) {
  if (isQX) {
    $done();
    return;
  }
  $done({
    title: title,
    content: content,
    icon: allOk ? "checkmark.shield" : "exclamationmark.shield",
    "icon-color": allOk ? "#34C759" : "#FF3B30",
  });
}

/* ---------- 业务逻辑 ---------- */

// 服务端按 C 段（/24）加白，条目可能是精确 IP 或 x.x.x.0/24。
// 任一侧为 /24 段时按前三段比较，两侧均为精确 IP 时要求全等。
function sameC24(a, b) {
  if (!a || !b) return false;
  a = String(a);
  b = String(b);
  if (a === b) return true;
  if (a.slice(-3) !== "/24" && b.slice(-3) !== "/24") return false;
  var pa = a.replace("/24", "").split(".");
  var pb = b.replace("/24", "").split(".");
  return (
    pa.length === 4 && pb.length === 4 && pa[0] === pb[0] && pa[1] === pb[1] && pa[2] === pb[2]
  );
}

function readHistory(key) {
  try {
    var h = JSON.parse(storeRead(key) || "[]");
    var cutoff = Date.now() - HIST_WINDOW_MS;
    return h.filter(function (e) {
      return e.ts > cutoff;
    });
  } catch (e) {
    return [];
  }
}

function isPanelInvocation() {
  try {
    return typeof $input !== "undefined" && $input && $input.purpose === "panel";
  } catch (e) {
    return false;
  }
}

function pad2(value) {
  return value < 10 ? "0" + value : String(value);
}

function describeLastAutoSuccess() {
  try {
    var state = JSON.parse(storeRead(LAST_SUCCESS_KEY) || "null");
    if (!state || !state.ts) return "最近自动成功：暂无";
    var d = new Date(state.ts);
    var timestamp =
      d.getFullYear() +
      "-" +
      pad2(d.getMonth() + 1) +
      "-" +
      pad2(d.getDate()) +
      " " +
      pad2(d.getHours()) +
      ":" +
      pad2(d.getMinutes()) +
      ":" +
      pad2(d.getSeconds());
    return (
      "最近自动成功：" +
      timestamp +
      " · " +
      (state.trigger || "unknown") +
      " · " +
      (state.interface || "unknown") +
      " · " +
      (state.currentIp || "unknown")
    );
  } catch (e) {
    return "最近自动成功：记录损坏";
  }
}

function apiErrorDetail(data) {
  var detail = "";
  if (data && typeof data === "object") {
    if (typeof data.message === "string") detail = data.message;
    else if (typeof data.error === "string") detail = data.error;
    else if (typeof data.detail === "string") detail = data.detail;
  }
  return sanitizeLogText(detail).slice(0, 120);
}

function describeApiError(status, data) {
  var detail = apiErrorDetail(data);
  if (!detail && data && data.code !== undefined && data.code !== null) {
    detail = sanitizeLogText("code=" + String(data.code));
  }
  return "HTTP " + (status || "?") + (detail ? "：" + detail : "：服务端返回错误");
}

function describeEmbeddedApiError(code, data) {
  var detail = apiErrorDetail(data);
  return "API " + code + (detail ? "：" + detail : "：服务端返回错误");
}

function isValidIpv4Value(value) {
  if (typeof value !== "string" || value.length === 0) return false;
  var parts = value.split("/");
  if (parts.length > 2 || (parts.length === 2 && parts[1] !== "24")) return false;
  var octets = parts[0].split(".");
  if (octets.length !== 4) return false;
  for (var i = 0; i < octets.length; i++) {
    if (!/^\d{1,3}$/.test(octets[i])) return false;
    var n = Number(octets[i]);
    if (n < 0 || n > 255) return false;
  }
  return true;
}

function isValidWhitelistEntry(entry, limit) {
  if (typeof entry === "string") return isValidIpv4Value(entry);
  if (!entry || typeof entry !== "object" || !isValidIpv4Value(entry.ip)) return false;
  if (entry.slot === null || entry.slot === undefined) return true;
  var slot = Number(entry.slot);
  return isFinite(slot) && Math.floor(slot) === slot && slot >= 0 && slot < limit;
}

function apiCall(token, slot, requestOptions, method) {
  requestOptions = requestOptions || {};
  method = method || "POST";
  // GET 只读查询；POST /add 把当前出口 IP 加白，带 slot 时钉固定槽位。
  var url = API_BASE + encodeURIComponent(token);
  if (method === "POST") {
    url += "/add";
    if (slot !== null && slot !== undefined && slot !== "") {
      url += "?slot=" + encodeURIComponent(slot);
    }
  }
  var opts = {
    url: url,
    headers: { "Content-Type": "application/json" },
  };
  if (method === "POST") opts.body = "";
  var timeout = requestOptions.timeout;
  if (timeout === null || timeout === undefined) timeout = REQUEST_TIMEOUT;
  if (timeout !== null) opts.timeout = timeout;

  return httpRequest(method, opts, 1, requestOptions.maxAttempts).then(function (r) {
    if (r.error) return { error: r.error };
    var data = null;
    try {
      data = JSON.parse(r.body);
    } catch (e) {}
    // 带槽位写入且本机 IP 已占用别的槽位 → 服务端 403 冲突，需去 UI 删旧槽位
    if (method === "POST" && r.status === 403) {
      return {
        error: "槽位冲突：本机 IP 已在其它槽位，请先去 UI 删除",
        conflict: true,
        currentIp: data && data.currentIp,
        httpStatus: r.status,
      };
    }
    if (r.status < 200 || r.status >= 300) {
      var httpApiCode = Number(data && data.code);
      return {
        error: describeApiError(r.status, data),
        httpStatus: r.status,
        apiCode: httpApiCode >= 400 ? httpApiCode : undefined,
      };
    }
    if (!data) return { error: "响应不是有效 JSON (HTTP " + (r.status || "?") + ")", httpStatus: r.status };
    var embeddedCode = Number(data.code);
    if (embeddedCode >= 400) {
      return {
        error: describeEmbeddedApiError(embeddedCode, data),
        httpStatus: r.status,
        apiCode: embeddedCode,
      };
    }
    if (
      typeof data.enabled !== "boolean" ||
      !Array.isArray(data.whitelist) ||
      typeof data.limit !== "number" ||
      typeof data.currentIp !== "string" ||
      data.currentIp.length === 0
    ) {
      return { error: "响应字段缺失 (HTTP " + r.status + ")", httpStatus: r.status };
    }
    if (
      !isFinite(data.limit) ||
      Math.floor(data.limit) !== data.limit ||
      data.limit <= 0 ||
      data.limit > 100 ||
      data.whitelist.length > data.limit ||
      !isValidIpv4Value(data.currentIp) ||
      !data.whitelist.every(function (entry) {
        return isValidWhitelistEntry(entry, data.limit);
      })
    ) {
      return { error: "响应字段无效 (HTTP " + r.status + ")", httpStatus: r.status };
    }
    // whitelist 元素为 {ip, slot} 对象（旧版曾是纯 IP 字符串）：记下 ip→slot 再摊平成 IP 数组
    var raw = data.whitelist;
    data.slotOf = {};
    data.currentSlot = null;
    raw.forEach(function (e) {
      var ip = e && typeof e === "object" ? e.ip : e;
      if (e && typeof e === "object" && e.slot !== null && e.slot !== undefined) {
        data.slotOf[e.ip] = e.slot;
      }
      if (sameC24(ip, data.currentIp)) {
        data.currentSlot = e && typeof e === "object" && e.slot !== undefined ? e.slot : null;
      }
    });
    data.whitelist = raw.map(function (e) {
      return e && typeof e === "object" ? e.ip : e;
    });
    data.httpStatus = r.status;
    if (embeddedCode >= 0) data.apiCode = embeddedCode;
    data.applied =
      data.enabled === true &&
      data.whitelist.some(function (ip) {
        return sameC24(ip, data.currentIp);
      });
    return data;
  });
}

function ensureWhitelisted(item, index, requestOptions) {
  requestOptions = requestOptions || {};
  var kvState = STORE_PREFIX + index;
  var kvHist = STORE_PREFIX + "hist_" + index;
  var cellular = onCellular();
  var ctx = { kvState: kvState, kvHist: kvHist, slot: item.slot };
  var requiresSlot = item.slot !== null && item.slot !== undefined && item.slot !== "";

  function complete(st) {
    st.ready =
      st.applied === true &&
      (!requiresSlot || (st.currentSlot !== null && st.currentSlot !== undefined && Number(st.currentSlot) === Number(item.slot)));
    if (st.applied) {
      var hist = readHistory(kvHist);
      var last = hist.length ? hist[hist.length - 1] : null;
      if (!last || last.ip !== st.currentIp) {
        hist.push({ ip: st.currentIp, src: cellular ? "cell" : "fixed", ts: Date.now() });
        storeWrite(JSON.stringify(hist.slice(-10)), kvHist);
      }
    }
    ctx.st = st;
    return ctx;
  }

  if (requestOptions.readOnly || requestOptions.preflight) {
    return apiCall(item.token, item.slot, requestOptions, "GET").then(function (st) {
      complete(st);
      if (requestOptions.readOnly || st.error || st.enabled === false || st.ready) return ctx;
      return apiCall(item.token, item.slot, requestOptions, "POST").then(complete);
    });
  }

  return apiCall(item.token, item.slot, requestOptions, "POST").then(complete);
}

// 每 token 一行：不含 token，只含白名单/坑位信息；蜂窝加的 IP 标 📶
function describe(index, ctx) {
  var st = ctx.st;
  var pin = ctx.slot !== null && ctx.slot !== undefined && ctx.slot !== "" ? " 📌" + ctx.slot : "";
  var head = "#" + (index + 1) + pin + " ";
  if (st.error) return head + "❌ " + st.error;
  if (st.enabled === false) return head + "⚠️ 防火墙未启用";
  if (!st.ready) {
    var reason = st.applied ? "固定槽位未生效" : "加白未生效";
    return head + "❌ " + reason + " " + st.whitelist.length + "/" + st.limit;
  }

  var hist = readHistory(ctx.kvHist);
  var cellIps = {};
  hist.forEach(function (e) {
    if (e.src === "cell") cellIps[e.ip] = true;
  });
  var slotOf = st.slotOf || {};
  var ips = st.whitelist
    .map(function (ip) {
      var slotTag = slotOf[ip] !== undefined ? " 📌" + slotOf[ip] : "";
      return ip + slotTag + (cellIps[ip] ? " 📶" : "") + (sameC24(ip, st.currentIp) ? " ←" : "");
    })
    .join("\n    ");
  return head + "✅ " + st.whitelist.length + "/" + st.limit + "\n    " + ips;
}

// 分隔符兼容 , | ; 、；非 pgnfw_ 开头的段（如未修改的占位提示）直接忽略。
// 每段可带可选 @槽位 后缀：pgnfw_xxx@0 → 钉槽位 0；无后缀则 slotless。
var tokens = (getArgumentTokens() || storeRead(TOKENS_KEY) || INLINE_TOKENS || "")
  .split(/[,|;、\s]+/)
  .map(function (s) {
    return s.trim();
  })
  .filter(function (s) {
    return s.indexOf("pgnfw_") === 0;
  })
  .map(function (s) {
    var at = s.indexOf("@");
    if (at === -1) return { token: s, slot: null };
    var n = parseInt(s.slice(at + 1), 10);
    return { token: s.slice(0, at), slot: isNaN(n) ? null : n };
  });

var triggerName = getTriggerName();
var STABILIZATION_DELAYS_MS = [3000, 5000, 8000];

function runEnsureRound(requestOptions, attempt, total) {
  var startedAt = Date.now();
  return Promise.all(
    tokens.map(function (t, i) {
      return ensureWhitelisted(t, i, requestOptions);
    })
  ).then(function (results) {
    logRound(results, attempt || 1, total || 1, startedAt);
    return results;
  });
}

function runEnsurePlan() {
  var needsStabilization = triggerName === "network-changed" || triggerName === "engine-started";
  if (!needsStabilization) {
    var regularOptions = null;
    var regularTimeout = timeoutValue(7);
    if (isPanelInvocation() && triggerName === "auto-interval") {
      regularOptions = { readOnly: true, timeout: regularTimeout, maxAttempts: 1 };
    } else if (isPanelInvocation() && triggerName === "button") {
      regularOptions = { preflight: true, timeout: regularTimeout };
    } else if (triggerName === "cron") {
      regularOptions = { preflight: true, timeout: regularTimeout };
    }
    return runEnsureRound(regularOptions, 1, 1);
  }

  var eventRequestOptions = { maxAttempts: 1, timeout: timeoutValue(5), preflight: true };
  var sequence = Promise.resolve(null);
  STABILIZATION_DELAYS_MS.forEach(function (waitMs, index) {
    sequence = sequence.then(function () {
      return delay(waitMs).then(function () {
        return runEnsureRound(eventRequestOptions, index + 1, STABILIZATION_DELAYS_MS.length);
      });
    });
  });
  return sequence;
}

function completeRun(results, eventLease) {
  var okCount = 0;
  var exitIp = "?";
  var lines = [];
  var changed = false;

  for (var i = 0; i < results.length; i++) {
    var st = results[i].st;
    if (st.ready) okCount++;
    if (st.currentIp) exitIp = st.currentIp;
    lines.push(describe(i, results[i]));

    var state = (st.currentIp || "?") + "|" + (st.ready ? "1" : "0");
    if (storeRead(results[i].kvState) !== state) {
      storeWrite(state, results[i].kvState);
      changed = true;
    }
  }

  var allOk = okCount === results.length;
  if (allOk && isAutomaticTrigger(triggerName)) {
    storeWrite(
      JSON.stringify({
        ts: Date.now(),
        trigger: triggerName,
        currentIp: exitIp,
        interface: getPrimaryInterface(),
      }),
      LAST_SUCCESS_KEY
    );
  }
  var title =
    "po0 加白 " + okCount + "/" + results.length + " · 出口 " + exitIp + (onCellular() ? " 📶" : "");
  var content = lines.join("\n");
  if (isPanelInvocation()) content += "\n\n" + describeLastAutoSuccess();

  // 成功态仅在出口 IP / 加白状态变化时通知；失败/未生效必须每次弹。
  // 面板 auto-interval 是只读后台刷新，只更新卡片缓存，不发送系统通知。
  if ((changed || !allOk) && triggerName !== "auto-interval") {
    notify("po0 防火墙加白", title, content);
  }
  releaseEventLease(eventLease);
  finish(title, content, allOk);
}

function failRun(error, eventLease) {
  releaseEventLease(eventLease);
  var errorText = sanitizeLogText(error && error.message ? error.message : error) || "未知脚本异常";
  if (triggerName !== "auto-interval") notify("po0 防火墙加白", "脚本异常", errorText);
  finish("po0 加白：脚本异常", errorText, false);
}

if (tokens.length === 0) {
  if (triggerName !== "auto-interval") {
    notify(
      "po0 防火墙加白",
      "未配置 token",
      "模块参数 tokens / 存储 key po0fw_tokens / 脚本内 INLINE_TOKENS 三选一填入 pgnfw_ token"
    );
  }
  finish("po0 加白：未配置 token", "请填入 pgnfw_ token，多个用 | 分割", false);
} else {
  var eventLease = null;
  Promise.resolve()
    .then(function () {
      return prepareEventLease(triggerName);
    })
    .then(function (lease) {
      eventLease = lease;
      if (lease.coalesced) {
        if (typeof console !== "undefined" && typeof console.log === "function") {
          console.log(
            "[po0fw] trigger=" +
              triggerName +
              " coalesced=yes interface=" +
              getPrimaryInterface() +
              " windowMs=" +
              EVENT_COALESCE_MS
          );
        }
        finish("po0 加白：已合并重复网络事件", "已有稳定窗口任务正在确认当前出口", true);
        return null;
      }
      return runEnsurePlan();
    })
    .then(function (results) {
      if (results !== null) completeRun(results, eventLease);
    })
    .catch(function (error) {
      failRun(error, eventLease);
    });
}
