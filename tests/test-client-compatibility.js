#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const scriptPath = path.join(__dirname, "..", "scripts", "po0-firewall-whitelist.js");
const source = fs.readFileSync(scriptPath, "utf8");
const token = "pgnfw_compatibility_fixture";

function responseBody() {
  return JSON.stringify({
    enabled: true,
    currentIp: "198.51.100.0/24",
    limit: 5,
    whitelist: [{ ip: "198.51.100.0/24", slot: null }],
  });
}

function clientGlobals(client, requests, store, logs) {
  const common = {
    Promise,
    Date,
    JSON,
    encodeURIComponent,
    decodeURIComponent,
    parseInt,
    isNaN,
    setTimeout(callback) {
      queueMicrotask(callback);
      return 1;
    },
    console: {
      log(message) {
        logs.push(String(message));
      },
    },
    $network: { v4: { primaryInterface: "pdp_ip0" }, v6: {} },
  };

  if (client === "quantumultx") {
    return {
      ...common,
      $task: {
        fetch(options) {
          requests.push({ ...options });
          return Promise.resolve({ statusCode: 200, body: responseBody() });
        },
      },
      $prefs: {
        valueForKey(key) {
          return store.has(key) ? store.get(key) : null;
        },
        setValueForKey(value, key) {
          store.set(key, value);
          return true;
        },
      },
      $notify() {},
    };
  }

  const environmentByClient = {
    surge: { "surge-version": "6.9.1" },
    shadowrocket: { "shadowrocket-version": "2.2.68" },
    stash: { "stash-version": "2.8.0" },
    loon: { "loon-version": "3.2.4" },
  };
  return {
    ...common,
    $argument: client === "loon" ? { tokens: token } : `tokens=${token}`,
    $environment: environmentByClient[client],
    ...(client === "surge"
      ? { $cronexp: "*/10 * * * *", $script: { name: "po0-fw-cron", type: "cron" } }
      : { $script: { name: "po0-fw-cron", type: "cron" } }),
    ...(client === "loon" ? { $loon: {} } : {}),
    $httpClient: {
      post(options, callback) {
        requests.push({ ...options, method: "POST" });
        queueMicrotask(() => callback(null, { status: 200 }, responseBody()));
      },
      get(options, callback) {
        requests.push({ ...options, method: "GET" });
        queueMicrotask(() => callback(null, { status: 200 }, responseBody()));
      },
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
    $notification: { post() {} },
  };
}

function runClient(client) {
  const requests = [];
  const store = new Map();
  if (client === "quantumultx") store.set("po0fw_tokens", token);
  const logs = [];

  return new Promise((resolve, reject) => {
    const watchdog = global.setTimeout(() => reject(new Error(`${client} did not call $done`)), 1000);
    const context = clientGlobals(client, requests, store, logs);
    context.$done = (result) => {
      global.clearTimeout(watchdog);
      resolve({ requests, store, logs, result });
    };

    try {
      vm.runInNewContext(source, context, { filename: scriptPath });
    } catch (error) {
      global.clearTimeout(watchdog);
      reject(error);
    }
  });
}

(async () => {
  const expectedTimeout = {
    surge: 7,
    shadowrocket: 7,
    stash: 7,
    loon: 7000,
    quantumultx: 7000,
  };

  for (const client of Object.keys(expectedTimeout)) {
    const run = await runClient(client);
    assert.equal(run.requests.length, 1, `${client} should complete one successful cron request`);
    assert.equal(run.requests[0].timeout, expectedTimeout[client], `${client} timeout unit regressed`);
    assert.equal(run.requests[0].method, "GET", `${client} cron should use the read-only preflight`);
    assert.equal(
      run.requests[0].url,
      `https://124.221.69.228/api/firewall/${encodeURIComponent(token)}`,
      `${client} did not deliver the configured token to the request URL`,
    );
    assert.equal(JSON.parse(run.store.get("po0_fw_last_auto_success")).trigger, "cron");
    assert.doesNotMatch(run.logs.join("\n"), new RegExp(token));
  }

  console.log("proxy-client compatibility tests passed");
})().catch((error) => {
  console.error(error.stack || error);
  process.exitCode = 1;
});
