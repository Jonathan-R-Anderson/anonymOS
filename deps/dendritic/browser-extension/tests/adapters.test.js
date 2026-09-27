"use strict";

const assert = require("assert");
const fs = require("fs");
const path = require("path");

require("../src/adapter-registry.js");
const registry = globalThis.ManiwaniSourceAdapters;

class FakeField {
  constructor(value) {
    this.value = value || "";
    this.events = [];
  }
  focus() {}
  dispatchEvent(event) {
    this.events.push(event.type);
  }
}

class FakeRoot {
  constructor(nodes) {
    this.nodes = nodes || {};
  }
  querySelector(selector) {
    return this.nodes[selector] || null;
  }
}

function fixture(adapterId, threadId) {
  const adapter = registry.adapters.find((item) => item.id === adapterId);
  const body = new FakeField();
  const name = new FakeField();
  const subject = new FakeField();
  const thread = new FakeField(threadId);
  const submit = new FakeField();
  const form = new FakeRoot({
    [adapter.thread[0]]: thread,
    [adapter.body[0]]: body,
    [adapter.name[0]]: name,
    [adapter.subject[0]]: subject,
    [adapter.submit[0]]: submit
  });
  const documentLike = new FakeRoot({[adapter.form[0]]: form});
  return {adapter, body, name, subject, submit, form, documentLike};
}

{
  const current = fixture("fourchan", "123456");
  const result = registry.fillDraft(current.adapter, {
    adapter_id: "fourchan",
    adapter_version: "1.0.0",
    source_thread_id: "123456",
    body: "visitor-controlled reply",
    subject: "subject",
    author_name: "name"
  }, current.documentLike, {
    hostname: "boards.4chan.org",
    pathname: "/g/thread/123456"
  });
  assert.equal(result.ok, true);
  assert.equal(current.body.value, "visitor-controlled reply");
  assert.equal(current.subject.value, "subject");
  assert.equal(current.name.value, "name");
  assert.deepEqual(current.body.events, ["input", "change"]);
}

{
  const current = fixture("vichan_7chan", "222");
  const result = registry.fillDraft(current.adapter, {
    adapter_id: "vichan_7chan",
    adapter_version: "1.0.0",
    source_thread_id: "999",
    body: "must not cross threads"
  }, current.documentLike, {
    hostname: "7chan.org",
    pathname: "/b/res/999.html"
  });
  assert.equal(result.ok, false);
  assert.equal(result.error, "thread_mismatch");
  assert.equal(current.body.value, "");
}

{
  const adapter = registry.findAdapter("fourchan", "1.0.0", {
    hostname: "boards.4chan.org.attacker.example"
  });
  assert.equal(adapter, null);
}

{
  const current = fixture("lynxchan_8chan_moe", "333");
  const result = registry.fillDraft(current.adapter, {
    adapter_id: "lynxchan_8chan_moe",
    adapter_version: "1.0.0",
    source_thread_id: "333",
    body: "lynxchan fixture"
  }, current.documentLike, {
    hostname: "8chan.moe",
    pathname: "/tech/res/333.html"
  });
  assert.equal(result.ok, true);
  assert.equal(current.body.value, "lynxchan fixture");
}

const sourceContent = fs.readFileSync(
  path.join(__dirname, "../src/source-content.js"),
  "utf8"
);
assert.equal(/\.click\s*\(/.test(sourceContent), false, "content script must not click submit");
assert.equal(/captcha.*(?:value|token)/i.test(sourceContent), false, "content script must not read CAPTCHA answers");

console.log("adapter tests passed");
