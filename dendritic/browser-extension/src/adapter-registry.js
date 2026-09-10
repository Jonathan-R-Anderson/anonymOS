"use strict";

(function (root) {
  const adapters = [
    {
      id: "fourchan",
      version: "1.0.0",
      hosts: ["boards.4chan.org", "boards.4channel.org"],
      path: /^\/[A-Za-z0-9_-]+\/thread\/([0-9]+)\/?$/,
      form: ["form[name='post']", "#postForm"],
      thread: ["input[name='resto']"],
      body: ["textarea[name='com']"],
      subject: ["input[name='sub']"],
      name: ["input[name='name']"],
      submit: ["input[type='submit']", "button[type='submit']"],
      challenge: [
        "#captchaContainer",
        ".captcha-root",
        "iframe[src*='captcha']",
        "iframe[src*='challenge']"
      ]
    },
    {
      id: "vichan_7chan",
      version: "1.0.0",
      hosts: ["7chan.org", "www.7chan.org"],
      path: /^\/[A-Za-z0-9_-]+\/res\/([0-9]+)(?:\.html)?\/?$/,
      form: ["form[name='post']", "form[action*='post.php']"],
      thread: ["input[name='thread']"],
      body: ["textarea[name='body']", "#body"],
      subject: ["input[name='subject']"],
      name: ["input[name='name']"],
      submit: ["input[name='post']", "button[type='submit']", "input[type='submit']"],
      challenge: [
        ".captcha",
        "#captcha",
        ".g-recaptcha",
        ".h-captcha",
        "iframe[src*='captcha']"
      ]
    },
    {
      id: "lynxchan_8chan_moe",
      version: "1.0.0",
      hosts: ["8chan.moe", "www.8chan.moe"],
      path: /^\/[A-Za-z0-9_-]+\/res\/([0-9]+)(?:\.html)?\/?$/,
      form: ["#post-form", "form[action*='newReply']", "form[action*='post']"],
      thread: ["input[name='threadId']", "input[name='thread']"],
      body: ["textarea[name='message']", "#fieldMessage", "textarea[name='body']"],
      subject: ["input[name='subject']", "#fieldSubject"],
      name: ["input[name='name']", "#fieldName"],
      submit: ["button[type='submit']", "input[type='submit']"],
      challenge: [
        ".captchaDiv",
        "#captchaDiv",
        ".h-captcha",
        "iframe[src*='captcha']",
        "[data-sitekey]"
      ]
    }
  ];

  function firstWithin(rootNode, selectors) {
    for (const selector of selectors || []) {
      const node = rootNode.querySelector(selector);
      if (node) return node;
    }
    return null;
  }

  function matchesDraft(adapter, draft, locationLike) {
    if (!adapter || !draft || !locationLike) return false;
    if (!adapter.hosts.includes(String(locationLike.hostname || "").toLowerCase())) return false;
    if (draft.adapter_id !== adapter.id || draft.adapter_version !== adapter.version) return false;
    const match = adapter.path.exec(String(locationLike.pathname || ""));
    return Boolean(match && match[1] === String(draft.source_thread_id));
  }

  function findAdapter(adapterId, adapterVersion, locationLike) {
    return adapters.find(function (adapter) {
      return adapter.id === adapterId &&
        adapter.version === adapterVersion &&
        adapter.hosts.includes(String(locationLike.hostname || "").toLowerCase());
    }) || null;
  }

  function setTextField(field, value) {
    if (!field || value === null || value === undefined || value === "") return false;
    field.focus();
    field.value = String(value);
    for (const type of ["input", "change"]) {
      field.dispatchEvent(new Event(type, {bubbles: true}));
    }
    return true;
  }

  function fillDraft(adapter, draft, documentLike, locationLike) {
    if (!matchesDraft(adapter, draft, locationLike)) {
      return {ok: false, error: "destination_mismatch"};
    }
    const form = firstWithin(documentLike, adapter.form);
    if (!form) return {ok: false, error: "form_not_found"};
    const threadField = firstWithin(form, adapter.thread);
    if (threadField && String(threadField.value) !== String(draft.source_thread_id)) {
      return {ok: false, error: "thread_mismatch"};
    }
    const body = firstWithin(form, adapter.body);
    if (!body) return {ok: false, error: "body_field_not_found"};

    setTextField(body, draft.body);
    setTextField(firstWithin(form, adapter.subject), draft.subject);
    setTextField(firstWithin(form, adapter.name), draft.author_name);
    const challenge = firstWithin(form, adapter.challenge) ||
      firstWithin(documentLike, adapter.challenge);
    const submit = firstWithin(form, adapter.submit);
    return {ok: true, form: form, body: body, challenge: challenge, submit: submit};
  }

  root.ManiwaniSourceAdapters = {
    adapters: adapters,
    findAdapter: findAdapter,
    fillDraft: fillDraft,
    firstWithin: firstWithin,
    matchesDraft: matchesDraft
  };
})(typeof globalThis !== "undefined" ? globalThis : this);
