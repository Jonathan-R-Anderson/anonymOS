"use strict";

for (const button of document.querySelectorAll("[data-maniwani-extension-handoff]")) {
  button.hidden = false;
}

document.addEventListener("click", function (event) {
  const button = event.target.closest("[data-maniwani-extension-handoff]");
  if (!button) return;
  event.preventDefault();
  const status = document.querySelector("[data-maniwani-extension-status]");
  const capabilityUrl = button.getAttribute("data-capability-url");
  button.disabled = true;
  if (status) status.textContent = "Preparing the source form…";

  fetch(capabilityUrl, {
    method: "POST",
    credentials: "same-origin",
    headers: {"Accept": "application/json"}
  }).then(function (response) {
    return response.json().then(function (payload) {
      if (!response.ok) throw new Error(payload.error || ("HTTP " + response.status));
      return payload;
    });
  }).then(function (payload) {
    return chrome.runtime.sendMessage({
      type: "maniwani:start-handoff",
      apiOrigin: location.origin,
      publicId: payload.id,
      capability: payload.capability,
      expiresAt: payload.expires_at,
      launch: payload.launch
    });
  }).then(function (result) {
    if (!result || !result.ok) throw new Error((result && result.error) || "extension_unavailable");
    if (status) {
      status.textContent =
        "Source tab opened. Complete its CAPTCHA, review the filled form, and click Submit yourself.";
    }
  }).catch(function (error) {
    button.disabled = false;
    if (status) {
      status.textContent =
        "The extension could not start (" + error.message + "). Use the manual copy controls.";
    }
  });
});
