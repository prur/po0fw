#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

const root = path.join(__dirname, "..");
const sha = "5c98e31edcb8c42eb885e1a7a93e958dd092aed7";
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

const localScript = fs.readFileSync(path.join(root, "scripts/po0-firewall-whitelist.js"), "utf8");
const pinnedScript = execFileSync("git", ["show", `${sha}:scripts/po0-firewall-whitelist.js`], {
  cwd: root,
  encoding: "utf8",
});
assert.equal(pinnedScript, localScript, "the immutable pinned commit does not contain the tested script blob");

console.log("pinned script-reference tests passed");
