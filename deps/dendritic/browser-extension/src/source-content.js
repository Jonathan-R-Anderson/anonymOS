"use strict";

function sendEvent(event, detail) {
  chrome.runtime.sendMessage({
    type: "maniwani:source-event",
    event: event,
    detail: detail || ""
  });
}

function showBanner(message, kind) {
  let banner = document.getElementById("maniwani-remote-reply-banner");
  if (!banner) {
    banner = document.createElement("div");
    banner.id = "maniwani-remote-reply-banner";
    document.documentElement.appendChild(banner);
  }
  banner.dataset.kind = kind || "info";
  banner.textContent = message;
}

function stageDraft(draft) {
  const adapter = ManiwaniSourceAdapters.findAdapter(
    draft.adapter_id,
    draft.adapter_version,
    location
  );
  if (!adapter) {
    showBanner("Maniwani stopped: this source adapter or host is not allowlisted.", "error");
    sendEvent("form_not_found", "adapter_or_host_mismatch");
    return;
  }
  const result = ManiwaniSourceAdapters.fillDraft(adapter, draft, document, location);
  if (!result.ok) {
    showBanner(
      "Maniwani could not safely identify this reply form. Your draft remains available for manual copy.",
      "error"
    );
    sendEvent("form_not_found", result.error);
    return;
  }

  result.body.classList.add("maniwani-filled-field");
  if (result.challenge) result.challenge.classList.add("maniwani-visitor-action");
  if (result.submit) result.submit.classList.add("maniwani-visitor-action");
  showBanner(
    "Draft filled by Maniwani. Review it, complete this site's CAPTCHA or login, then click Submit yourself.",
    "ready"
  );
  sendEvent(result.challenge ? "challenge_present" : "form_ready");

  let reported = false;
  result.form.addEventListener("submit", function () {
    if (reported) return;
    reported = true;
    sendEvent("user_submitted");
  }, true);
  (result.challenge || result.body).scrollIntoView({behavior: "smooth", block: "center"});
}

chrome.runtime.sendMessage({type: "maniwani:source-ready"}, function (response) {
  if (chrome.runtime.lastError) return;
  if (!response || !response.ok) {
    if (response && response.error === "waiting_for_source_page") {
      showBanner(
        "Complete this source site's browser challenge. Maniwani will resume when the thread page loads.",
        "ready"
      );
    } else if (response && response.error !== "handoff_expired") {
      showBanner("Maniwani handoff unavailable: " + response.error, "error");
    }
    return;
  }
  stageDraft(response.draft);
});
