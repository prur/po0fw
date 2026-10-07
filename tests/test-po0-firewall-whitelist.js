#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const SCRIPT_PATH = path.join(__dirname, "..", "scripts", "po0-firewall-whitelist.js");
const SCRIPT_SOURCE = fs.readFileSync(SCRIPT_PATH, "utf8");

function stateBody(currentIp, whitelistIps) {
  return JSON.stringify({
    enabled: true,
    currentIp,
    limit: 5,
    whitelist: (whitelistIps || [currentIp]).map((entry) =>
      typeof entry === "string" ? { ip: entry, slot: null } : entry,
    ),
  });
}

function successBody(ip) {
  return stateBody(ip, [ip]);
}

function runSurgeScript({
  eventName,
  trigger,
  cronexp,
  argument = "tokens=pgnfw_test_secret",
  scriptType = "event",
  responses,
  initialStore = {},
  sharedStore = null,
  sessionID = "TESTSESSION",
  storeReadError = null,
  storeWriteSucceeds = true,
  onDelay = null,
  clock = { now: Date.now() },
  scheduleTimer = null,
}) {
  const posts = [];
  const gets = [];
  const delays = [];
  const logs = [];
  const notifications = [];
  const store = sharedStore || new Map(Object.entries(initialStore));
  let responseIndex = 0;

  return new Promise((resolve, reject) => {
    const watchdog = global.setTimeout(() => reject(new Error("script did not call $done")), 1000);

    const context = {
      Promise,
      Date: class extends Date {
        static now() { return clock.now; }
      },
      JSON,
      encodeURIComponent,
      decodeURIComponent,
      parseInt,
      isNaN,
      console: {
        log(message) {
          logs.push(String(message));
        },
      },
      setTimeout(callback, ms) {
        delays.push(ms);
        if (onDelay) onDelay(ms, store);
        if (scheduleTimer) scheduleTimer(callback, ms);
        else queueMicrotask(() => { clock.now += ms; callback(); });
        return delays.length;
      },
      $argument: argument,
      $environment: { "surge-version": "6.9.1" },
      $network: {
        v4: { primaryInterface: "pdp_ip0", primaryAddress: "10.0.0.2" },
        v6: {},
      },
      $event: eventName ? { name: eventName, data: {} } : undefined,
      $trigger: trigger,
      $cronexp: cronexp,
      $input: scriptType === "generic" ? { purpose: "panel", panelName: "po0-fw" } : undefined,
      $script: {
        name:
          scriptType === "generic"
            ? "po0-fw-panel"
            : scriptType === "cron"
              ? "po0-fw-cron"
              : "po0-fw-event",
        type: scriptType,
        sessionID,
      },
      $persistentStore: {
        read(key) {
          if (storeReadError) throw new Error(storeReadError);
          return store.has(key) ? store.get(key) : null;
        },
        write(value, key) {
          if (!storeWriteSucceeds) return false;
          store.set(key, value);
          return true;
        },
      },
      $notification: {
        post(title, subtitle, body) {
          notifications.push({ title, subtitle, body });
        },
      },
      $httpClient: {
        post(options, callback) {
          posts.push({ ...options, at: clock.now });
          const response = responses[Math.min(responseIndex, responses.length - 1)];
          responseIndex += 1;
          const metadata = response.missingStatus
            ? null
            : { status: response.status === undefined ? 200 : response.status };
          queueMicrotask(() => {
            clock.now += response.elapsedMs || 0;
            callback(response.error || null, metadata, response.body);
          });
        },
        get(options, callback) {
          gets.push({ ...options, at: clock.now });
          const response = responses[Math.min(responseIndex, responses.length - 1)];
          responseIndex += 1;
          const metadata = response.missingStatus
            ? null
            : { status: response.status === undefined ? 200 : response.status };
          queueMicrotask(() => {
            clock.now += response.elapsedMs || 0;
            callback(response.error || null, metadata, response.body);
          });
        },
      },
      $done(result) {
        global.clearTimeout(watchdog);
        resolve({ result, posts, gets, delays, logs, notifications, store, endedAt: clock.now });
      },
    };

    try {
      vm.runInNewContext(SCRIPT_SOURCE, context, { filename: SCRIPT_PATH });
    } catch (error) {
      global.clearTimeout(watchdog);
      reject(error);
    }
  });
}

async function testNetworkChangeAlwaysConfirmsThreeTimes() {
  const run = await runSurgeScript({
    eventName: "network-changed",
    responses: [
      { body: successBody("198.51.100.0/24") },
      { body: successBody("198.51.100.0/24") },
      { body: successBody("203.0.113.0/24") },
    ],
  });

  assert.equal(run.gets.length, 3, "network change must confirm the exit three times even after success");
  assert.equal(run.posts.length, 0);
  assert.deepEqual(run.delays, [100, 3000, 5000, 24900]);
  assert.match(run.result.title, /203\.0\.113\.0\/24/);
  assert.equal(run.logs.length, 3, "each stabilization round should leave one diagnostic log line");
  assert.match(run.logs[0], /trigger=network-changed/);
  assert.match(run.logs[0], /attempt=1\/3/);
  assert.match(run.logs[2], /currentIp=203\.0\.113\.0\/24/);
  assert.match(run.logs[2], /httpStatus=200/);
  assert.doesNotMatch(run.logs.join("\n"), /pgnfw_test_secret|api\/firewall/);
  const lastSuccess = JSON.parse(run.store.get("po0_fw_last_auto_success"));
  assert.equal(lastSuccess.trigger, "network-changed");
  assert.equal(lastSuccess.currentIp, "203.0.113.0/24");
  assert.equal(lastSuccess.interface, "pdp_ip0");
  assert.equal(typeof lastSuccess.ts, "number");
  assert.equal(JSON.parse(run.store.get("po0_fw_event_lease")).owner, "TESTSESSION");
}

async function testNetworkChangeReadsEveryRoundAndWritesOnlyWhenNeeded() {
  const oldIp = "198.51.100.0/24";
  const newIp = "203.0.113.0/24";
  const run = await runSurgeScript({
    eventName: "network-changed",
    responses: [
      { body: stateBody(oldIp, [oldIp]) },
      { body: stateBody(oldIp, [oldIp]) },
      { body: stateBody(newIp, [oldIp]) },
      { body: stateBody(newIp, [oldIp, newIp]) },
    ],
  });

  assert.equal(run.gets.length, 3);
  assert.equal(run.posts.length, 1, "only the newly observed network should require a write");
  assert.deepEqual(run.delays, [100, 3000, 5000, 24900]);
  assert.match(run.result.title, /203\.0\.113\.0\/24/);
}

async function testDuplicateNetworkEventIsCoalesced() {
  const run = await runSurgeScript({
    eventName: "network-changed",
    initialStore: { po0_fw_event_lease: String(Date.now()) },
    responses: [{ body: successBody("198.51.100.0/24") }],
  });

  assert.equal(run.gets.length, 0);
  assert.equal(run.posts.length, 0);
  assert.equal(run.delays.length, 0);
  assert.match(run.result.title, /已合并重复网络事件/);
  assert.match(run.logs.join("\n"), /coalesced=yes/);
}

async function testLeaseWriteFailureFailsOpenWithDiagnostic() {
  const run = await runSurgeScript({
    eventName: "network-changed",
    sessionID: "LEASE-WRITE-FAIL",
    storeWriteSucceeds: false,
    responses: [
      { body: successBody("198.51.100.0/24") },
      { body: successBody("198.51.100.0/24") },
      { body: successBody("198.51.100.0/24") },
    ],
  });

  assert.equal(run.gets.length, 3, "lease storage failure must not block whitelisting");
  assert.match(run.logs.join("\n"), /lease=unavailable/);
}

async function testConcurrentNetworkEventsChooseOneLeaseOwner() {
  const sharedStore = new Map();
  const responses = [
    { body: successBody("198.51.100.0/24") },
    { body: successBody("198.51.100.0/24") },
    { body: successBody("198.51.100.0/24") },
  ];
  const runs = await Promise.all([
    runSurgeScript({ eventName: "network-changed", sessionID: "LEASE-A", sharedStore, responses }),
    runSurgeScript({ eventName: "network-changed", sessionID: "LEASE-B", sharedStore, responses }),
  ]);

  assert.equal(runs.reduce((sum, run) => sum + run.gets.length, 0), 3);
  assert.equal(runs.filter((run) => /已合并重复网络事件/.test(run.result.title)).length, 1);
}

async function testLeaseSettlementYieldsToCompetingWriter() {
  let replaced = false;
  const run = await runSurgeScript({
    eventName: "network-changed",
    sessionID: "LEASE-A",
    onDelay(ms, store) {
      if (!replaced && ms === 100) {
        replaced = true;
        store.set("po0_fw_event_lease", JSON.stringify({ ts: Date.now(), owner: "LEASE-B" }));
      }
    },
    responses: [{ body: successBody("198.51.100.0/24") }],
  });

  assert.equal(run.gets.length, 0);
  assert.equal(run.posts.length, 0);
  assert.match(run.result.title, /已合并重复网络事件/);
  assert.equal(JSON.parse(run.store.get("po0_fw_event_lease")).owner, "LEASE-B");
}

async function testStaleLeaseCanBeTakenOver() {
  const stale = JSON.stringify({ ts: Date.now() - 61000, owner: "OLD" });
  const run = await runSurgeScript({
    eventName: "network-changed",
    sessionID: "NEW",
    initialStore: { po0_fw_event_lease: stale },
    responses: [
      { body: successBody("198.51.100.0/24") },
      { body: successBody("198.51.100.0/24") },
      { body: successBody("198.51.100.0/24") },
    ],
  });

  assert.equal(run.gets.length, 3);
  assert.equal(JSON.parse(run.store.get("po0_fw_event_lease")).owner, "NEW");
}

async function testOldOwnerDoesNotReleaseNewOwnerLease() {
  let replaced = false;
  const run = await runSurgeScript({
    eventName: "network-changed",
    sessionID: "OLD-OWNER",
    onDelay(ms, store) {
      if (!replaced && ms >= 3000) {
        replaced = true;
        store.set("po0_fw_event_lease", JSON.stringify({ ts: Date.now(), owner: "NEW-OWNER" }));
      }
    },
    responses: [
      { body: successBody("198.51.100.0/24") },
      { body: successBody("198.51.100.0/24") },
      { body: successBody("198.51.100.0/24") },
    ],
  });

  assert.equal(JSON.parse(run.store.get("po0_fw_event_lease")).owner, "NEW-OWNER");
}

async function testEventWorstCaseBudgetStaysUnderModuleTimeout() {
  const oldIp = "198.51.100.0/24";
  const newIp = "203.0.113.0/24";
  for (const latency of [0, 2500, 5000]) {
    for (const needsWrite of [false, true]) {
      const clock = { now: 1760000000000 };
      const startedAt = clock.now;
      const responses = [];
      for (let i = 0; i < 3; i += 1) {
        responses.push({ body: stateBody(newIp, needsWrite ? [oldIp] : [oldIp, newIp]), elapsedMs: latency });
        if (needsWrite) responses.push({ body: stateBody(newIp, [oldIp, newIp]), elapsedMs: latency });
      }
      const run = await runSurgeScript({ eventName: "network-changed", responses, clock });
      assert.equal(run.gets.length, 3);
      assert.equal(run.posts.length, needsWrite ? 3 : 0);
      assert.ok(run.gets[2].at >= startedAt + 33000, "final GET covers lease expiry plus settling");
      const elapsed = run.endedAt - startedAt;
      assert.ok(elapsed <= 46100, `event took ${elapsed}ms`);
      assert.ok(elapsed < 60000);
      if (latency === 5000 && needsWrite) assert.equal(elapsed, 46100);
      if (latency === 0) assert.equal(elapsed, 33000);
    }
  }
}

async function testSecondSwitchDuringLeaseIsObservedByLiveOwner() {
  for (const switchAt of [20000, 29999]) {
    const start = 1760000000000;
    const clock = { now: start };
    const sharedStore = new Map();
    const timers = [];
    const scheduleTimer = (callback, ms) => timers.push({ callback, at: clock.now + ms });
    const oldIp = "198.51.100.0/24";
    const newIp = "203.0.113.0/24";
    let ownerDone = false;
    let follower;
    const owner = runSurgeScript({
      eventName: "network-changed", sessionID: "OWNER", clock, sharedStore, scheduleTimer,
      responses: [
        { body: successBody(oldIp) }, { body: successBody(oldIp) },
        { body: stateBody(newIp, [oldIp]) }, { body: successBody(newIp) },
      ],
    }).then((run) => { ownerDone = true; return run; });
    scheduleTimer(() => {
      assert.equal(ownerDone, false, "the coalesced event must still have a live owner");
      follower = runSurgeScript({
        eventName: "network-changed", sessionID: "FOLLOWER", clock, sharedStore, scheduleTimer,
        responses: [{ body: successBody(newIp) }],
      });
    }, switchAt);
    // Drain promise chains before advancing to the next virtual timer. No real network or sleeps.
    while (!ownerDone) {
      for (let i = 0; i < 50; i += 1) await Promise.resolve();
      if (ownerDone) break;
      timers.sort((a, b) => a.at - b.at);
      assert.ok(timers.length, "expected an outstanding owner timer");
      const timer = timers.shift();
      clock.now = timer.at;
      timer.callback();
    }
    const run = await owner;
    const coalesced = await follower;
    assert.equal(coalesced.gets.length, 0);
    assert.equal(coalesced.posts.length, 0);
    assert.equal(run.gets[2].at, start + 33000);
    assert.equal(run.posts.length, 1, "the owner whitelists the second switch");
    assert.match(run.result.title, /203\.0\.113\.0\/24/);
  }
}

async function testExpiredLeaseAllowsNewOwnerAndCannotExtendOldDeadline() {
  const start = 1760000000000;
  const clock = { now: start };
  let replaced = false;
  const run = await runSurgeScript({
    eventName: "network-changed", sessionID: "OLD", clock,
    onDelay(ms, store) {
      if (ms === 5000 && !replaced) {
        replaced = true;
        store.set("po0_fw_event_lease", JSON.stringify({ ts: start + 30000, owner: "NEW" }));
      }
    },
    responses: [{ body: successBody("198.51.100.0/24") }],
  });
  assert.equal(run.endedAt, start + 33000, "a successor must not extend the old owner's deadline");
  assert.equal(JSON.parse(run.store.get("po0_fw_event_lease")).owner, "NEW");
  const next = await runSurgeScript({
    eventName: "network-changed", sessionID: "NEXT", clock: { now: start + 30000 },
    initialStore: { po0_fw_event_lease: JSON.stringify({ ts: start, owner: "OLD" }) },
    responses: [{ body: successBody("203.0.113.0/24") }],
  });
  assert.equal(next.gets.length, 3, "exactly at TTL, a genuine event may acquire a new lease");
  assert.equal(JSON.parse(next.store.get("po0_fw_event_lease")).owner, "NEXT");
}

async function testNetworkChangeUsesBoundedIndependentAttempts() {
  const run = await runSurgeScript({
    eventName: "network-changed",
    responses: [
      { error: "offline" },
      { error: "offline" },
      { error: "offline" },
    ],
  });

  assert.equal(run.gets.length, 3, "event stabilization rounds must replace nested HTTP retries");
  assert.equal(run.posts.length, 0);
  assert.deepEqual(
    run.gets.map((request) => request.timeout),
    [5, 5, 5],
    "each Surge event request must have a five-second cap",
  );
  assert.deepEqual(run.delays, [100, 3000, 5000, 24900]);
  assert.match(run.result.title, /po0 加白 0\/1/);
  assert.equal(run.store.has("po0_fw_last_auto_success"), false);
}

async function testFinalRoundFailureIsNotReportedAsAutomaticSuccess() {
  const run = await runSurgeScript({
    eventName: "network-changed",
    responses: [
      { body: successBody("198.51.100.0/24") },
      { body: successBody("203.0.113.0/24") },
      { error: "final confirmation offline" },
    ],
  });

  assert.equal(run.gets.length, 3);
  assert.equal(run.posts.length, 0);
  assert.match(run.result.title, /po0 加白 0\/1/);
  assert.equal(run.store.has("po0_fw_last_auto_success"), false);
  assert.ok(run.notifications.length >= 1, "a failed final confirmation must notify");
}

async function testMultipleTokensAreConfirmedInEveryRound() {
  const run = await runSurgeScript({
    eventName: "network-changed",
    argument: "tokens=pgnfw_fixture_one,pgnfw_fixture_two",
    responses: [
      { body: successBody("198.51.100.0/24") },
      { body: successBody("192.0.2.0/24") },
      { body: successBody("198.51.100.0/24") },
      { body: successBody("192.0.2.0/24") },
      { body: successBody("203.0.113.0/24") },
      { body: successBody("203.0.114.0/24") },
    ],
  });

  assert.equal(run.gets.length, 6);
  assert.equal(run.posts.length, 0);
  assert.match(run.result.title, /po0 加白 2\/2/);
  assert.match(run.result.content, /203\.0\.113\.0\/24/);
  assert.match(run.result.content, /203\.0\.114\.0\/24/);
  assert.equal(run.logs.length, 3);
  assert.match(run.logs[2], /token#1 status=ok/);
  assert.match(run.logs[2], /token#2 status=ok/);
  assert.doesNotMatch(run.logs.join("\n"), /pgnfw_fixture_one|pgnfw_fixture_two/);
}

async function testEngineStartUsesTheSameStabilizationPlan() {
  const run = await runSurgeScript({
    eventName: "engine-started",
    responses: [
      { body: successBody("198.51.100.0/24") },
      { body: successBody("198.51.100.0/24") },
      { body: successBody("198.51.100.0/24") },
    ],
  });

  assert.equal(run.gets.length, 3);
  assert.equal(run.posts.length, 0);
  assert.deepEqual(run.delays, [100, 3000, 5000, 24900]);
  assert.deepEqual(run.gets.map((request) => request.timeout), [5, 5, 5]);
}

async function testCronSkipsWriteWhenAlreadyApplied() {
  const run = await runSurgeScript({
    cronexp: "*/10 * * * *",
    scriptType: "cron",
    responses: [{ body: successBody("198.51.100.0/24") }],
  });

  assert.equal(run.gets.length, 1);
  assert.equal(run.posts.length, 0);
  assert.equal(run.gets[0].timeout, 7);
  assert.equal(JSON.parse(run.store.get("po0_fw_last_auto_success")).trigger, "cron");
}

async function testCronKeepsTransientRetriesAndRecordsSuccess() {
  const run = await runSurgeScript({
    cronexp: "*/10 * * * *",
    scriptType: "cron",
    responses: [
      { error: "offline" },
      { error: "offline" },
      { body: successBody("198.51.100.0/24") },
    ],
  });

  assert.equal(run.gets.length, 3);
  assert.equal(run.posts.length, 0);
  assert.deepEqual(run.gets.map((request) => request.timeout), [7, 7, 7]);
  assert.deepEqual(run.delays, [1500, 3000]);
  assert.equal(run.logs.length, 1);
  assert.match(run.logs[0], /trigger=cron/);
  const lastSuccess = JSON.parse(run.store.get("po0_fw_last_auto_success"));
  assert.equal(lastSuccess.trigger, "cron");
}

async function testMissingHttpStatusRetriesAndFailsClosed() {
  const missingStatus = { missingStatus: true, body: successBody("198.51.100.0/24") };
  const run = await runSurgeScript({
    trigger: "button",
    scriptType: "generic",
    responses: [missingStatus, missingStatus, missingStatus],
  });

  assert.equal(run.gets.length, 3);
  assert.equal(run.posts.length, 0);
  assert.match(run.result.content, /HTTP 响应缺少有效状态码/);
}

async function testTransportErrorRedactsCredential() {
  const rawError = "timeout https://124.221.69.228/api/firewall/pgnfw_test_secret/add";
  const run = await runSurgeScript({
    trigger: "button",
    scriptType: "generic",
    responses: [{ error: rawError }, { error: rawError }, { error: rawError }],
  });

  assert.match(run.result.content, /pgnfw_REDACTED/);
  assert.doesNotMatch(run.result.content, /pgnfw_test_secret/);
  assert.doesNotMatch(run.logs.join("\n"), /pgnfw_test_secret/);
}

async function testJsonHttpErrorIsRetriedAndRenderedClearly() {
  const errorResponse = {
    status: 429,
    body: JSON.stringify({ code: 429, message: "Too many requests" }),
  };
  const run = await runSurgeScript({
    trigger: "button",
    scriptType: "generic",
    responses: [errorResponse, errorResponse, errorResponse],
  });

  assert.equal(run.gets.length, 3, "HTTP 429 should use the normal transient retry budget");
  assert.equal(run.posts.length, 0);
  assert.deepEqual(run.delays, [1500, 3000]);
  assert.match(run.result.content, /HTTP 429/);
  assert.match(run.result.content, /Too many requests/);
  assert.doesNotMatch(run.result.content, /undefined/);
  assert.match(run.logs.join("\n"), /httpStatus=429/);
  assert.match(run.logs.join("\n"), /apiCode=429/);
}

async function testMalformedSuccessResponseIsRejectedWithoutUndefinedFields() {
  const run = await runSurgeScript({
    trigger: "button",
    scriptType: "generic",
    responses: [{ status: 200, body: JSON.stringify({ code: 400, message: "temporary failure" }) }],
  });

  assert.match(run.result.content, /API 400：temporary failure/);
  assert.doesNotMatch(run.result.content, /undefined/);
  assert.match(run.logs.join("\n"), /httpStatus=200/);
  assert.match(run.logs.join("\n"), /error=API 400/);
}

async function testMalformedSuccessSchemaIsRejectedFailClosed() {
  const malformedBodies = [
    JSON.stringify({ enabled: true, currentIp: "999.1.1.1/24", limit: 5, whitelist: [] }),
    JSON.stringify({ enabled: true, currentIp: "198.51.100.1/24", limit: 5, whitelist: [] }),
    JSON.stringify({ enabled: true, currentIp: "01.51.100.0/24", limit: 5, whitelist: [] }),
    JSON.stringify({ enabled: true, currentIp: "198.51.100.0/24", limit: 5, whitelist: [{ slot: null }] }),
    JSON.stringify({
      enabled: true,
      currentIp: "198.51.100.0/24",
      limit: 5.5,
      whitelist: [{ ip: "198.51.100.0/24", slot: null }],
    }),
  ];

  for (const body of malformedBodies) {
    const run = await runSurgeScript({
      trigger: "button",
      scriptType: "generic",
      responses: [{ status: 200, body }],
    });
    assert.equal(run.posts.length, 0);
    assert.match(run.result.content, /响应字段无效 \(HTTP 200\)/);
    assert.doesNotMatch(run.result.content, /undefined/);
  }
}

async function testEmbeddedApi429IsRetried() {
  const embeddedError = {
    status: 200,
    body: JSON.stringify({ code: 429, message: "request frequency too high for pgnfw_test_secret" }),
  };
  const run = await runSurgeScript({
    trigger: "button",
    scriptType: "generic",
    responses: [embeddedError, embeddedError, embeddedError],
  });

  assert.equal(run.gets.length, 3);
  assert.deepEqual(run.delays, [1500, 3000]);
  assert.match(run.result.content, /API 429：request frequency too high for pgnfw_REDACTED/);
  assert.doesNotMatch(run.result.content, /pgnfw_test_secret/);
}

async function testPanelAutoIntervalUsesReadOnlyStatus() {
  const run = await runSurgeScript({
    trigger: "auto-interval",
    scriptType: "generic",
    responses: [{ body: successBody("198.51.100.0/24") }],
  });

  assert.equal(run.gets.length, 1);
  assert.equal(run.posts.length, 0, "automatic panel refresh must never mutate the whitelist");
  assert.equal(run.gets[0].timeout, 7);
  assert.match(run.result.title, /po0 加白 1\/1/);
}

async function testStashTileIsReadOnlyAndSilent() {
  const currentIp = "203.0.113.0/24";
  const run = await runSurgeScript({
    scriptType: "tile",
    trigger: undefined,
    responses: [{ body: stateBody(currentIp, ["198.51.100.0/24"]) }],
  });

  assert.equal(run.gets.length, 1);
  assert.equal(run.posts.length, 0);
  assert.equal(run.notifications.length, 0);
  assert.match(run.result.title, /po0 加白 0\/1/);
}

async function testPanelRedactsPersistedAutomaticSuccessFields() {
  const run = await runSurgeScript({
    trigger: "auto-interval",
    scriptType: "generic",
    initialStore: {
      po0_fw_last_auto_success: JSON.stringify({
        ts: Date.now(),
        trigger: "pgnfw_trigger_secret",
        interface: "pgnfw_interface_secret",
        currentIp: "pgnfw_ip_secret",
      }),
    },
    responses: [{ body: successBody("198.51.100.0/24") }],
  });

  assert.doesNotMatch(run.result.content, /pgnfw_(?:trigger|interface|ip)_secret/);
  assert.match(run.result.content, /pgnfw_REDACTED/);
  assert.match(run.result.content, /unknown/);
}

async function testPanelAutoIntervalMissingTokenDoesNotNotify() {
  const run = await runSurgeScript({
    trigger: "auto-interval",
    scriptType: "generic",
    argument: null,
    responses: [{ body: successBody("198.51.100.0/24") }],
  });

  assert.match(run.result.title, /未配置 token/);
  assert.equal(run.notifications.length, 0);
}

async function testPanelAutoIntervalExceptionIsRedactedAndDoesNotNotify() {
  const run = await runSurgeScript({
    trigger: "auto-interval",
    scriptType: "generic",
    argument: null,
    storeReadError: "store failed for pgnfw_test_secret",
    responses: [{ body: successBody("198.51.100.0/24") }],
  });

  assert.match(run.result.content, /pgnfw_REDACTED/);
  assert.doesNotMatch(run.result.content, /pgnfw_test_secret/);
  assert.equal(run.notifications.length, 0);
}

async function testPanelAutoIntervalFailureDoesNotNotify() {
  const errorResponse = {
    status: 429,
    body: JSON.stringify({ code: 429, message: "Too many requests" }),
  };
  const run = await runSurgeScript({
    trigger: "auto-interval",
    scriptType: "generic",
    responses: [errorResponse, errorResponse, errorResponse],
  });

  assert.match(run.result.content, /HTTP 429/);
  assert.equal(run.gets.length, 1);
  assert.equal(run.delays.length, 0);
  assert.equal(run.notifications.length, 0, "background panel refresh must not emit system notifications");
}

async function testPanelButtonAddsOnlyWhenCurrentNetworkIsMissing() {
  const currentIp = "203.0.113.0/24";
  const run = await runSurgeScript({
    trigger: "button",
    scriptType: "generic",
    responses: [
      { body: stateBody(currentIp, ["198.51.100.0/24"]) },
      { body: stateBody(currentIp, ["198.51.100.0/24", currentIp]) },
    ],
  });

  assert.equal(run.gets.length, 1);
  assert.equal(run.posts.length, 1);
  assert.equal(run.gets[0].timeout, 7);
  assert.equal(run.posts[0].timeout, 7);
  assert.match(run.result.title, /po0 加白 1\/1/);
}

async function testButtonWorstCaseRetryBudgetStaysUnderModuleTimeout() {
  const oldIp = "198.51.100.0/24";
  const newIp = "203.0.113.0/24";
  const retry = { status: 429, body: JSON.stringify({ code: 429, message: "busy" }) };
  const run = await runSurgeScript({
    trigger: "button",
    scriptType: "generic",
    responses: [
      retry,
      retry,
      { body: stateBody(newIp, [oldIp]) },
      retry,
      retry,
      { body: stateBody(newIp, [oldIp, newIp]) },
    ],
  });

  assert.equal(run.gets.length, 3);
  assert.equal(run.posts.length, 3);
  const budgetMs =
    run.delays.reduce((sum, ms) => sum + ms, 0) +
    [...run.gets, ...run.posts].reduce((sum, request) => sum + request.timeout * 1000, 0);
  assert.equal(budgetMs, 51000);
  assert.ok(budgetMs < 60000);
}

async function testPinnedSlotPreflightUpgradesSlotlessEntry() {
  const ip = "198.51.100.0/24";
  const run = await runSurgeScript({
    trigger: "button",
    scriptType: "generic",
    argument: "tokens=pgnfw_test_secret@0",
    responses: [
      { body: stateBody(ip, [{ ip, slot: null }]) },
      { body: stateBody(ip, [{ ip, slot: 0 }]) },
    ],
  });

  assert.equal(run.gets.length, 1);
  assert.equal(run.posts.length, 1);
  assert.match(run.posts[0].url, /\/add\?slot=0$/);
  assert.match(run.result.title, /po0 加白 1\/1/);
}

async function testPinnedSlotPreflightSurfacesWrongSlotConflict() {
  const ip = "198.51.100.0/24";
  const run = await runSurgeScript({
    trigger: "button",
    scriptType: "generic",
    argument: "tokens=pgnfw_test_secret@0",
    responses: [
      { body: stateBody(ip, [{ ip, slot: 1 }]) },
      { status: 403, body: JSON.stringify({ code: 403, message: "slot conflict", currentIp: ip }) },
    ],
  });

  assert.equal(run.gets.length, 1);
  assert.equal(run.posts.length, 1);
  assert.match(run.result.content, /槽位冲突/);
}

async function testSlotless403IsNotMislabeledAsSlotConflict() {
  const ip = "198.51.100.0/24";
  const run = await runSurgeScript({
    trigger: "button",
    scriptType: "generic",
    responses: [
      { body: stateBody(ip, []) },
      { status: 403, body: JSON.stringify({ code: 403, message: "forbidden" }) },
    ],
  });

  assert.match(run.result.content, /HTTP 403：forbidden/);
  assert.doesNotMatch(run.result.content, /槽位冲突/);
  assert.match(run.logs.join("\n"), /apiCode=403/);
}

async function testPinned403RejectsUntrustedCurrentIp() {
  const ip = "198.51.100.0/24";
  const run = await runSurgeScript({
    trigger: "button",
    scriptType: "generic",
    argument: "tokens=pgnfw_test_secret@0",
    responses: [
      { body: stateBody(ip, []) },
      {
        status: 403,
        body: JSON.stringify({ code: 403, message: "slot conflict", currentIp: "pgnfw_leaked_secret" }),
      },
    ],
  });

  assert.match(run.result.content, /HTTP 403：slot conflict/);
  assert.doesNotMatch(run.result.content, /槽位冲突：本机 IP/);
  assert.doesNotMatch(run.result.content, /pgnfw_leaked_secret/);
  assert.doesNotMatch(run.logs.join("\n"), /pgnfw_leaked_secret/);
  assert.match(run.logs.join("\n"), /apiCode=403/);
  for (const value of run.store.values()) assert.doesNotMatch(String(value), /pgnfw_leaked_secret/);
}

async function testMalformedWhitelistSlotsAreRejected() {
  const ip = "198.51.100.0/24";
  for (const entry of [
    { ip, slot: "0" },
    { ip, slot: false },
    { ip, slot: "" },
    { ip },
  ]) {
    const run = await runSurgeScript({
      trigger: "button",
      scriptType: "generic",
      argument: "tokens=pgnfw_test_secret@0",
      responses: [{ body: stateBody(ip, [entry]) }],
    });
    assert.equal(run.posts.length, 0);
    assert.match(run.result.content, /响应字段无效 \(HTTP 200\)/);
  }
}

async function testMalformedTokenSlotSuffixIsRejected() {
  const run = await runSurgeScript({
    trigger: "button",
    scriptType: "generic",
    argument: "tokens=pgnfw_test_secret@not-a-slot",
    responses: [{ body: successBody("198.51.100.0/24") }],
  });

  assert.equal(run.gets.length, 0);
  assert.equal(run.posts.length, 0);
  assert.match(run.result.title, /未配置 token/);
}

async function testConfiguredSlotMustFitServerLimit() {
  const ip = "198.51.100.0/24";
  const run = await runSurgeScript({
    trigger: "button",
    scriptType: "generic",
    argument: "tokens=pgnfw_test_secret@9",
    responses: [{ body: stateBody(ip, []) }],
  });

  assert.equal(run.gets.length, 1);
  assert.equal(run.posts.length, 0);
  assert.match(run.result.content, /配置槽位超出范围：应为 0-4/);
}

async function testPinnedSlotPreflightSkipsWriteWhenSlotMatches() {
  const ip = "198.51.100.0/24";
  const run = await runSurgeScript({
    trigger: "button",
    scriptType: "generic",
    argument: "tokens=pgnfw_test_secret@0",
    responses: [{ body: stateBody(ip, [{ ip, slot: 0 }]) }],
  });

  assert.equal(run.gets.length, 1);
  assert.equal(run.posts.length, 0);
  assert.match(run.result.title, /po0 加白 1\/1/);
}

async function testPanelButtonSkipsPostWhenAlreadyApplied() {
  const run = await runSurgeScript({
    trigger: "button",
    scriptType: "generic",
    responses: [{ body: successBody("198.51.100.0/24") }],
  });

  assert.equal(run.gets.length, 1);
  assert.equal(run.posts.length, 0);
  assert.match(run.result.title, /po0 加白 1\/1/);
}

async function testPanelShowsLastAutomaticSuccessWithoutReplacingIt() {
  const saved = JSON.stringify({
    ts: 1760000000000,
    trigger: "network-changed",
    currentIp: "198.51.100.0/24",
    interface: "pdp_ip0",
  });
  const run = await runSurgeScript({
    trigger: "button",
    scriptType: "generic",
    initialStore: { po0_fw_last_auto_success: saved },
    responses: [{ body: successBody("203.0.113.0/24") }],
  });

  assert.equal(run.gets.length, 1);
  assert.equal(run.posts.length, 0);
  assert.match(run.result.content, /最近自动成功/);
  assert.match(run.result.content, /network-changed/);
  assert.match(run.result.content, /198\.51\.100\.0\/24/);
  assert.equal(run.store.get("po0_fw_last_auto_success"), saved, "manual panel refresh must not replace auto state");
}

(async () => {
  await testNetworkChangeAlwaysConfirmsThreeTimes();
  await testNetworkChangeReadsEveryRoundAndWritesOnlyWhenNeeded();
  await testDuplicateNetworkEventIsCoalesced();
  await testLeaseWriteFailureFailsOpenWithDiagnostic();
  await testConcurrentNetworkEventsChooseOneLeaseOwner();
  await testLeaseSettlementYieldsToCompetingWriter();
  await testStaleLeaseCanBeTakenOver();
  await testOldOwnerDoesNotReleaseNewOwnerLease();
  await testEventWorstCaseBudgetStaysUnderModuleTimeout();
  await testSecondSwitchDuringLeaseIsObservedByLiveOwner();
  await testExpiredLeaseAllowsNewOwnerAndCannotExtendOldDeadline();
  await testNetworkChangeUsesBoundedIndependentAttempts();
  await testFinalRoundFailureIsNotReportedAsAutomaticSuccess();
  await testMultipleTokensAreConfirmedInEveryRound();
  await testEngineStartUsesTheSameStabilizationPlan();
  await testCronSkipsWriteWhenAlreadyApplied();
  await testCronKeepsTransientRetriesAndRecordsSuccess();
  await testMissingHttpStatusRetriesAndFailsClosed();
  await testTransportErrorRedactsCredential();
  await testJsonHttpErrorIsRetriedAndRenderedClearly();
  await testMalformedSuccessResponseIsRejectedWithoutUndefinedFields();
  await testMalformedSuccessSchemaIsRejectedFailClosed();
  await testEmbeddedApi429IsRetried();
  await testPanelAutoIntervalUsesReadOnlyStatus();
  await testStashTileIsReadOnlyAndSilent();
  await testPanelRedactsPersistedAutomaticSuccessFields();
  await testPanelAutoIntervalMissingTokenDoesNotNotify();
  await testPanelAutoIntervalExceptionIsRedactedAndDoesNotNotify();
  await testPanelAutoIntervalFailureDoesNotNotify();
  await testPanelButtonAddsOnlyWhenCurrentNetworkIsMissing();
  await testButtonWorstCaseRetryBudgetStaysUnderModuleTimeout();
  await testPinnedSlotPreflightUpgradesSlotlessEntry();
  await testPinnedSlotPreflightSurfacesWrongSlotConflict();
  await testSlotless403IsNotMislabeledAsSlotConflict();
  await testPinned403RejectsUntrustedCurrentIp();
  await testMalformedWhitelistSlotsAreRejected();
  await testMalformedTokenSlotSuffixIsRejected();
  await testConfiguredSlotMustFitServerLimit();
  await testPinnedSlotPreflightSkipsWriteWhenSlotMatches();
  await testPanelButtonSkipsPostWhenAlreadyApplied();
  await testPanelShowsLastAutomaticSuccessWithoutReplacingIt();
  console.log("po0 firewall JavaScript tests passed");
})().catch((error) => {
  console.error(error.stack || error);
  process.exitCode = 1;
});
