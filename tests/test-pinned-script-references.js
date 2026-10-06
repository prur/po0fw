#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const root = path.join(__dirname, "..");
const sha = "ccc62ffbb254f48227becf44c695e4830445e5a1";
const pinnedUrl = `https://raw.githubusercontent.com/prur/po0fw/${sha}/scripts/po0-firewall-whitelist.js`;
const expectedReferenceCounts = new Map([
  ["surge/po0-firewall-whitelist.sgmodule", 4],
  ["loon/po0-firewall-whitelist.plugin", 2],
  ["stash/po0-firewall-whitelist.stoverride", 1],
  ["quantumultx/po0-firewall-whitelist.snippet", 1],
  ["shadowrocket/po0-firewall-whitelist.srmodule", 2],
]);
const scriptUrlPattern =
  /https:\/\/raw\.githubusercontent\.com\/[^\s"',]+\/scripts\/po0-firewall-whitelist\.js(?:\?[^\s"',]+)?/g;

for (const [relativePath, expectedCount] of expectedReferenceCounts) {
  const source = fs.readFileSync(path.join(root, relativePath), "utf8");
  const urls = source.match(scriptUrlPattern) || [];
  assert.equal(urls.length, expectedCount, `${relativePath} has an unexpected number of script references`);
  assert.deepEqual(
    [...new Set(urls)],
    [pinnedUrl],
    `${relativePath} contains a mutable or unaudited script reference`,
  );
}

console.log("pinned script-reference tests passed");
