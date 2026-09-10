"use strict";

const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");
const output = path.join(root, "dist");
const configuredOrigin = String(process.env.MANIWANI_ORIGIN || "http://localhost").replace(/\/+$/, "");
const parsedOrigin = new URL(configuredOrigin);
if (!["http:", "https:"].includes(parsedOrigin.protocol) || parsedOrigin.username || parsedOrigin.password) {
  throw new Error("MANIWANI_ORIGIN must be an http(s) origin without credentials.");
}
if (parsedOrigin.pathname !== "/" || parsedOrigin.search || parsedOrigin.hash) {
  throw new Error("MANIWANI_ORIGIN must not include a path, query, or fragment.");
}

const maniwaniMatch = parsedOrigin.origin + "/*";
const sourceMatches = [
  "https://boards.4chan.org/*",
  "https://boards.4channel.org/*",
  "https://7chan.org/*",
  "https://www.7chan.org/*",
  "https://8chan.moe/*",
  "https://www.8chan.moe/*"
];

const template = JSON.parse(
  fs.readFileSync(path.join(root, "manifest.template.json"), "utf8")
);
template.host_permissions = [maniwaniMatch].concat(sourceMatches);
template.content_scripts[0].matches = [maniwaniMatch];
template.content_scripts[1].matches = sourceMatches;

fs.mkdirSync(output, {recursive: true});
for (const filename of [
  "background.js",
  "maniwani-content.js",
  "adapter-registry.js",
  "source-content.js",
  "source-banner.css"
]) {
  fs.copyFileSync(path.join(root, "src", filename), path.join(output, filename));
}
fs.writeFileSync(
  path.join(output, "manifest.json"),
  JSON.stringify(template, null, 2) + "\n"
);
console.log("Built extension for " + parsedOrigin.origin + " in " + output);
