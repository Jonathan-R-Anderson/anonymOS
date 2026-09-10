"use strict";

importScripts("adapter-registry.js");

const pendingByTab = new Map();
const eventQueues = new Map();

function safeOrigin(value) {
  try {
    const parsed = new URL(value);
    if (!["http:", "https:"].includes(parsed.protocol) ||
        parsed.username || parsed.password ||
        parsed.pathname !== "/" || parsed.search || parsed.hash) {
      return null;
    }
    return parsed.origin;
  } catch (_error) {
    return null;
  }
}

function validateLaunch(message) {
  const launch = message.launch || {};
  const parsed = new URL(launch.source_url);
  const adapter = ManiwaniSourceAdapters.findAdapter(
    launch.adapter_id,
    launch.adapter_version,
    parsed
  );
  if (!adapter || parsed.protocol !== "https:" || parsed.hostname !== launch.source_host) {
    throw new Error("unsupported_destination");
  }
  return {adapter: adapter, sourceUrl: parsed.href};
}

function consumePendingHandoff(pending, tab, sendResponse) {
  let senderUrl;
  try {
    senderUrl = new URL(tab.url);
  } catch (_error) {
    sendResponse({ok: false, error: "invalid_source_url"});
    return;
  }
  const adapter = ManiwaniSourceAdapters.findAdapter(
    pending.adapterId,
    pending.adapterVersion,
    senderUrl
  );
  if (!adapter || senderUrl.origin !== new URL(pending.sourceUrl).origin) {
    sendResponse({ok: false, error: "source_tab_mismatch"});
    return;
  }
  const expectedUrl = new URL(pending.sourceUrl);
  if (senderUrl.pathname !== expectedUrl.pathname) {
    sendResponse({ok: false, error: "waiting_for_source_page"});
    return;
  }
  fetch(
    pending.apiOrigin + "/threads/outbound-replies/" +
      encodeURIComponent(pending.publicId) + "/consume-capability",
    {
      method: "POST",
      headers: {"Content-Type": "application/json", "Accept": "application/json"},
      body: JSON.stringify({capability: pending.capability})
    }
  ).then(function (response) {
    return response.json().then(function (payload) {
      if (!response.ok) throw new Error(payload.error || ("HTTP " + response.status));
      return payload;
    });
  }).then(function (draft) {
    if (draft.adapter_id !== pending.adapterId ||
        draft.adapter_version !== pending.adapterVersion ||
        new URL(draft.source_url).origin !== senderUrl.origin) {
      throw new Error("draft_destination_mismatch");
    }
    pendingByTab.delete(tab.id);
    return chrome.storage.session.remove("pending:" + tab.id).then(function () {
      return chrome.storage.session.set({
        ["event:" + tab.id]: {
          apiOrigin: pending.apiOrigin,
          publicId: pending.publicId,
          eventToken: draft.event_token,
          sequence: 0,
          expiresAt: Date.now() + (30 * 60 * 1000)
        }
      });
    }).then(function () {
      sendResponse({ok: true, draft: draft});
    });
  }).catch(function (error) {
    sendResponse({ok: false, error: error.message});
  });
}

chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
  if (!message || typeof message.type !== "string") return false;

  if (message.type === "maniwani:start-handoff") {
    try {
      const apiOrigin = safeOrigin(message.apiOrigin);
      if (!apiOrigin || !sender.tab || new URL(sender.tab.url).origin !== apiOrigin) {
        throw new Error("invalid_maniwani_origin");
      }
      const launch = validateLaunch(message);
      chrome.tabs.create({url: launch.sourceUrl, active: true}, function (tab) {
        if (chrome.runtime.lastError || !tab || typeof tab.id !== "number") {
          sendResponse({ok: false, error: "could_not_open_source_tab"});
          return;
        }
        const pending = {
          apiOrigin: apiOrigin,
          publicId: message.publicId,
          capability: message.capability,
          expiresAt: Date.parse(message.expiresAt),
          adapterId: launch.adapter.id,
          adapterVersion: launch.adapter.version,
          sourceUrl: launch.sourceUrl
        };
        pendingByTab.set(tab.id, pending);
        chrome.storage.session.set({["pending:" + tab.id]: pending}).then(function () {
          sendResponse({ok: true, tabId: tab.id});
        }).catch(function () {
          pendingByTab.delete(tab.id);
          sendResponse({ok: false, error: "could_not_store_handoff"});
        });
      });
    } catch (error) {
      sendResponse({ok: false, error: error.message});
    }
    return true;
  }

  if (message.type === "maniwani:source-ready") {
    if (!sender.tab || typeof sender.tab.id !== "number") {
      sendResponse({ok: false, error: "missing_source_tab"});
      return false;
    }
    const tab = sender.tab;
    const inMemory = pendingByTab.get(tab.id);
    const pendingPromise = inMemory
      ? Promise.resolve(inMemory)
      : chrome.storage.session.get("pending:" + tab.id).then(function (stored) {
          return stored["pending:" + tab.id];
        });
    pendingPromise.then(function (pending) {
      if (!pending || Date.now() >= pending.expiresAt) {
        pendingByTab.delete(tab.id);
        chrome.storage.session.remove("pending:" + tab.id);
        sendResponse({ok: false, error: "handoff_expired"});
        return;
      }
      pendingByTab.set(tab.id, pending);
      consumePendingHandoff(pending, tab, sendResponse);
    }).catch(function () {
      sendResponse({ok: false, error: "handoff_storage_unavailable"});
    });
    return true;
  }

  if (message.type === "maniwani:source-event") {
    if (!sender.tab || typeof sender.tab.id !== "number") return false;
    const tabId = sender.tab.id;
    const key = "event:" + tabId;
    const previous = eventQueues.get(tabId) || Promise.resolve();
    const current = previous.catch(function () {}).then(function () {
      return chrome.storage.session.get(key).then(function (stored) {
        const state = stored[key];
        if (!state || Date.now() >= state.expiresAt) throw new Error("event_token_expired");
        state.sequence += 1;
        return fetch(
          state.apiOrigin + "/threads/outbound-replies/" +
            encodeURIComponent(state.publicId) + "/events",
          {
            method: "POST",
            headers: {"Content-Type": "application/json", "Accept": "application/json"},
            body: JSON.stringify({
              event_token: state.eventToken,
              sequence: state.sequence,
              event: message.event,
              detail: String(message.detail || "").slice(0, 512)
            })
          }
        ).then(function (response) {
          if (!response.ok) throw new Error("event_rejected");
          return chrome.storage.session.set({[key]: state});
        });
      });
    });
    eventQueues.set(tabId, current);
    current.then(function () {
      sendResponse({ok: true});
    }).catch(function (error) {
      sendResponse({ok: false, error: error.message});
    }).finally(function () {
      if (eventQueues.get(tabId) === current) eventQueues.delete(tabId);
    });
    return true;
  }
  return false;
});

chrome.tabs.onRemoved.addListener(function (tabId) {
  pendingByTab.delete(tabId);
  eventQueues.delete(tabId);
  chrome.storage.session.remove(["pending:" + tabId, "event:" + tabId]);
});
