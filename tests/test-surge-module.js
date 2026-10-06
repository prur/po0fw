#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const modulePath = path.join(__dirname, "..", "surge", "po0-firewall-whitelist.sgmodule");
const source = fs.readFileSync(modulePath, "utf8");
const lines = source.split(/\r?\n/);
const PINNED_SCRIPT_SHA = "ccc62ffbb254f48227becf44c695e4830445e5a1";
const PINNED_SCRIPT_URL = `https://raw.githubusercontent.com/prur/po0fw/${PINNED_SCRIPT_SHA}/scripts/po0-firewall-whitelist.js`;

function lineStartingWith(prefix) {
  const line = lines.find((candidate) => candidate.startsWith(prefix));
  assert.ok(line, `missing module line: ${prefix}`);
  return line;
}

const cron = lineStartingWith("po0-fw-cron = ");
assert.match(cron, /type=cron/);
assert.match(cron, /cronexp="\*\/10 \* \* \* \*"/);
assert.match(cron, /wake-system=true/, "iOS must wake Surge for the ten-minute fallback");

const networkChanged = lineStartingWith("po0-fw-event = ");
assert.match(networkChanged, /event-name=network-changed/);

const engineStarted = lineStartingWith("po0-fw-start = ");
assert.match(engineStarted, /event-name=engine-started/);
assert.match(engineStarted, /timeout=60/);

for (const prefix of ["po0-fw-cron = ", "po0-fw-event = ", "po0-fw-start = ", "po0-fw-panel = "]) {
  assert.ok(lineStartingWith(prefix).includes(`script-path=${PINNED_SCRIPT_URL}`), `${prefix}must pin the audited script`);
}
assert.doesNotMatch(source, /raw\.githubusercontent\.com\/w0ven\/po0fw\/main\/scripts\/po0-firewall-whitelist\.js/);

console.log("Surge module tests passed");
