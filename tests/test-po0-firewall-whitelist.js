#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const SCRIPT_PATH = path.join(__dirname, "..", "scripts", "po0-firewall-whitelist.js");
const SCRIPT_SOURCE = fs.readFileSync(SCRIPT_PATH, "utf8");

function successBody(ip) {
  return JSON.stringify({
    enabled: true,
    currentIp: ip,
    limit: 5,
    whitelist: [{ ip, slot: null }],
  });
}

function runSurgeScript({
  eventName,
  trigger,
  cronexp,
  scriptType = "event",
  responses,
  initialStore = {},
}) {
  const posts = [];
  const delays = [];
  const logs = [];
  const notifications = [];
  const store = new Map(Object.entries(initialStore));
  let responseIndex = 0;

  return new Promise((resolve, reject) => {
    const watchdog = global.setTimeout(() => reject(new Error("script did not call $done")), 1000);

    const context = {
      Promise,
      Date,
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
        queueMicrotask(callback);
        return delays.length;
      },
      $argument: "tokens=pgnfw_test_secret",
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
      },
      $persistentStore: {
        read(key) {
          return store.has(key) ? store.get(key) : null;
        },
        write(value, key) {
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
          posts.push(options);
          const response = responses[Math.min(responseIndex, responses.length - 1)];
          responseIndex += 1;
          queueMicrotask(() => callback(response.error || null, { status: response.status || 200 }, response.body));
        },
        get() {
          throw new Error("unexpected GET");
        },
      },
      $done(result) {
        global.clearTimeout(watchdog);
        resolve({ result, posts, delays, logs, notifications, store });
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

  assert.equal(run.posts.length, 3, "network change must confirm the exit three times even after success");
  assert.deepEqual(run.delays, [3000, 5000, 8000]);
  assert.match(run.result.title, /203\.0\.113\.0\/24/);
  assert.equal(run.logs.length, 3, "each stabilization round should leave one diagnostic log line");
  assert.match(run.logs[0], /trigger=network-changed/);
  assert.match(run.logs[0], /attempt=1\/3/);
  assert.match(run.logs[2], /currentIp=203\.0\.113\.0\/24/);
  assert.doesNotMatch(run.logs.join("\n"), /pgnfw_test_secret|api\/firewall/);
  const lastSuccess = JSON.parse(run.store.get("po0_fw_last_auto_success"));
  assert.equal(lastSuccess.trigger, "network-changed");
  assert.equal(lastSuccess.currentIp, "203.0.113.0/24");
  assert.equal(lastSuccess.interface, "pdp_ip0");
  assert.equal(typeof lastSuccess.ts, "number");
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

  assert.equal(run.posts.length, 3, "event stabilization rounds must replace nested HTTP retries");
  assert.deepEqual(
    run.posts.map((post) => post.timeout),
    [8, 8, 8],
    "each Surge event request must have an eight-second cap",
  );
  assert.deepEqual(run.delays, [3000, 5000, 8000]);
  assert.match(run.result.title, /脚本异常|po0 加白 0\/1/);
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

  assert.equal(run.posts.length, 3);
  assert.deepEqual(run.delays, [3000, 5000, 8000]);
  assert.deepEqual(run.posts.map((post) => post.timeout), [8, 8, 8]);
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

  assert.equal(run.posts.length, 3);
  assert.deepEqual(run.posts.map((post) => post.timeout), [15, 15, 15]);
  assert.deepEqual(run.delays, [1500, 3000]);
  assert.equal(run.logs.length, 1);
  assert.match(run.logs[0], /trigger=cron/);
  const lastSuccess = JSON.parse(run.store.get("po0_fw_last_auto_success"));
  assert.equal(lastSuccess.trigger, "cron");
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

  assert.equal(run.posts.length, 1);
  assert.match(run.result.content, /最近自动成功/);
  assert.match(run.result.content, /network-changed/);
  assert.match(run.result.content, /198\.51\.100\.0\/24/);
  assert.equal(run.store.get("po0_fw_last_auto_success"), saved, "manual panel refresh must not replace auto state");
}

(async () => {
  await testNetworkChangeAlwaysConfirmsThreeTimes();
  await testNetworkChangeUsesBoundedIndependentAttempts();
  await testEngineStartUsesTheSameStabilizationPlan();
  await testCronKeepsTransientRetriesAndRecordsSuccess();
  await testPanelShowsLastAutomaticSuccessWithoutReplacingIt();
  console.log("po0 firewall JavaScript tests passed");
})().catch((error) => {
  console.error(error.stack || error);
  process.exitCode = 1;
});
