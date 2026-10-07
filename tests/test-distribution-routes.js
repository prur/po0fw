#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const root = path.join(__dirname, "..");
const read = (file) => fs.readFileSync(path.join(root, file), "utf8");
const raw = "https://raw.githubusercontent.com/prur/po0fw/main/";
const modules = new Map([
  ["surge/po0-firewall-whitelist.sgmodule", "surge:///install-module?url={U}"],
  ["loon/po0-firewall-whitelist.plugin", "loon://import?plugin={U}"],
  ["stash/po0-firewall-whitelist.stoverride", "stash://install-override?url={U}"],
  ["shadowrocket/po0-firewall-whitelist.srmodule", "shadowrocket://install?module={U}"],
  ["egern/po0-firewall-whitelist.yaml", "egern:/modules/new?url={U}"],
  ["quantumultx/po0-firewall-whitelist.snippet", null],
]);
const readme = read("README.md");
const html = read("docs/index.html");

// README links work directly, without assuming that this fork has a Pages site.
for (const file of modules.keys()) {
  assert.ok(fs.existsSync(path.join(root, file)), `missing module: ${file}`);
  assert.ok(readme.includes(`](${raw}${file})`), `README lacks a fork URL for ${file}`);
}
assert.ok(readme.includes("[上游原版安装页](https://po0fw.uuuz.de/)"));
for (const [file, source] of [["README.md", readme], ["docs/index.html", html]]) {
  assert.ok(source.includes("https://github.com/w0ven/po0fw"), `${file} lost upstream credit`);
  assert.ok(source.includes("https://github.com/reallinzc/po0fw"), `${file} lost module credit`);
  assert.ok(!source.includes("https://prur.github.io/"), `${file} assumes an unverified Pages site`);
  for (const installer of ["install-linux.sh", "openwrt/install-openwrt.sh", "windows/install-windows.ps1"]) {
    assert.ok(source.includes(raw + installer), `${file} does not advertise the fork's ${installer}`);
  }
}
for (const file of [
  "README.md", "docs/index.html", "android/README.md",
  "install-linux.sh", "openwrt/install-openwrt.sh", "windows/install-windows.ps1",
]) {
  assert.ok(!read(file).includes("https://raw.githubusercontent.com/w0ven/po0fw/main"),
    `${file} silently routes an installation back to upstream main`);
}
assert.ok(read("android/README.md").includes(raw + "install-linux.sh"));
for (const file of ["install-linux.sh", "openwrt/install-openwrt.sh"]) {
  assert.ok(read(file).includes(`RAW_BASE="\${PO0FW_RAW:-${raw.slice(0, -1)}}"`),
    `${file} must download the fork worker by default and retain PO0FW_RAW overrides`);
}
const windowsInstaller = fs.readFileSync(path.join(root, "windows/install-windows.ps1"));
assert.deepEqual([...windowsInstaller.subarray(0, 3)], [0xef, 0xbb, 0xbf], "preserve the Windows PowerShell 5.1 BOM");
assert.ok(windowsInstaller.toString("utf8").includes(`[string]$RawBase = "${raw.slice(0, -1)}"`));

const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];
assert.equal(scripts.length, 1, "expected one self-contained installer script");

function element(attributes = "") {
  const listeners = {};
  const values = Object.fromEntries([...attributes.matchAll(/([\w-]+)="([^"]*)"/g)].map((m) => [m[1], m[2]]));
  return {
    dataset: { file: values["data-file"], scheme: values["data-scheme"] },
    value: "",
    textContent: "",
    classList: { add() {}, remove() {}, toggle() {} },
    addEventListener(event, callback) { listeners[event] = callback; },
    fire(event) {
      assert.ok(listeners[event], `missing ${event} listener for ${values["data-file"] || "token input"}`);
      listeners[event]();
    },
  };
}

// Execute the real page script and its actual data-file/data-scheme attributes.
// Cover local-file environments where storage or the modern clipboard is denied.
async function checkPage({ storageBlocked, clipboardMode }) {
  const anchors = [...html.matchAll(/<a\b([^>]*)>/g)]
    .filter((m) => m[1].includes("data-scheme="))
    .map((m) => element(m[1]));
  const buttons = [...html.matchAll(/<button\b([^>]*)>/g)]
    .filter((m) => m[1].includes("data-file="))
    .map((m) => element(m[1]));
  assert.equal(anchors.length, 5);
  assert.equal(buttons.length, modules.size);
  assert.deepEqual(new Set(buttons.map((b) => b.dataset.file)), new Set(modules.keys()));
  const input = element();
  const tokenDisplay = element();
  const copies = [];
  const storage = new Map([["po0fw_token", "pgnfw_saved"]]);
  let selectedTextarea;
  const document = {
    getElementById(id) { return id === "tok" ? input : element(); },
    querySelectorAll(selector) {
      return {
        "[data-t]": [tokenDisplay],
        "[data-scheme]": anchors,
        ".bc[data-file]": buttons,
        "#tabs button": [],
        ".pane": [],
        ".cb .cp": [],
      }[selector] || [];
    },
    body: { appendChild() {} },
    createElement(tag) {
      assert.equal(tag, "textarea");
      const textarea = { value: "", select() { selectedTextarea = textarea; }, remove() {} };
      return textarea;
    },
    execCommand(command) {
      assert.equal(command, "copy");
      copies.push(selectedTextarea.value);
      return true;
    },
  };
  const context = {
    document,
    localStorage: {
      getItem(key) {
        if (storageBlocked) throw new Error("Storage disabled for this origin");
        return storage.get(key);
      },
      setItem(key, value) {
        if (storageBlocked) throw new Error("Storage disabled for this origin");
        storage.set(key, value);
      },
    },
    navigator: clipboardMode === "absent" ? {} : {
      clipboard: {
        writeText(value) {
          if (clipboardMode === "rejected") return Promise.reject(new Error("Clipboard denied"));
          copies.push(value);
          return Promise.resolve();
        },
      },
    },
    setTimeout() {},
  };
  vm.runInNewContext(scripts[0][1], context, { filename: "docs/index.html", timeout: 1000 });
  assert.equal(input.value, storageBlocked ? "" : "pgnfw_saved");
  for (const token of ["", "pgnfw_test@0", "invalid token"]) {
    input.value = token;
    input.fire("input");
    assert.equal(tokenDisplay.textContent, token === "pgnfw_test@0" ? token : "pgnfw_你的token");
    for (const anchor of anchors) {
      anchor.fire("click");
      assert.equal(anchor.href, modules.get(anchor.dataset.file).replace("{U}", encodeURIComponent(raw + anchor.dataset.file)));
    }
    for (const button of buttons) {
      button.fire("click");
      await Promise.resolve();
      assert.equal(copies.pop(), raw + button.dataset.file, `wrong copied URL for ${button.dataset.file}`);
    }
  }
  if (!storageBlocked) assert.equal(storage.get("po0fw_token"), "pgnfw_test@0");
}

(async () => {
  for (const storageBlocked of [false, true]) {
    for (const clipboardMode of ["available", "absent", "rejected"]) {
      await checkPage({ storageBlocked, clipboardMode });
    }
  }
  console.log("fork distribution-route tests passed");
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
