// Binds the Tip button to the tested tip flow — roadmap P15, phase 2 last mile.
//
// This is DOM plumbing and nothing else. Every decision that matters — is the
// quote fresh, did the user confirm, did the payment actually complete — lives
// in tip-flow.js, which is tested without a browser. This file reads attributes,
// shows text, and forwards clicks.
//
// TWO CLICKS, NEVER ONE
// ---------------------
// Opening the dialog quotes nothing. The first "Send Tip" obtains a quote and
// SHOWS it; the button then becomes "Confirm and send", and only the second
// click authorises. That is what makes the confirmation explicit rather than
// implied by having typed a number.
//
// LOADED ON DEMAND
// ----------------
// The ethers bundle is ~640KB and almost nobody clicks Tip, so nothing is
// imported until the first click — the same reasoning the award route gives for
// serving tip-channel.js lazily.
//
// The page carries no secret. Its data attributes are the recipient's wallet
// (public, on chain), their slug and a label; the endpoint and manager arrive in
// the quote, and the private key never leaves the wallet extension.

import { createTipFlow, STATE, CHANNEL, DEFAULT_CHANNEL_FUNDING } from "./tip-flow.js";
import { loadEthers } from "./chain-load.js";

/** Default loader — the shared one, so there is a single dependency path. */
const defaultLoadEthers = (doc) => loadEthers(doc);

/**
 * Wire every Tip button under `root`.
 *
 * Uses ONE delegated listener rather than one per button, so posts added after
 * load (thread live-update) work without rebinding.
 */
export function bindTips(root, deps = {}) {
  const doc = deps.document || root.ownerDocument || root;
  const loadEthers = deps.loadEthers || (() => defaultLoadEthers(doc));
  const makeFlow = deps.createFlow || ((ethers) => createTipFlow({ ethers }));

  const dialog = root.querySelector("#tip-dialog");
  if (!dialog) return () => {};

  const who = root.querySelector("#tip-dialog-who");
  const amountEl = root.querySelector("#tip-amount");
  const sendEl = root.querySelector("#tip-send");
  const cancelEl = root.querySelector("#tip-cancel");
  const statusEl = root.querySelector("#tip-status");

  // Channel setup. Absent on a page still serving the older dialog markup, so
  // every use below is guarded — a missing panel must degrade to the previous
  // behaviour, not throw on the first click.
  const payPanel = root.querySelector("#tip-pay-panel");
  const setupPanel = root.querySelector("#tip-setup-panel");
  const fundEl = root.querySelector("#tip-fund-amount");
  const openEl = root.querySelector("#tip-open-channel");
  const setupCancelEl = root.querySelector("#tip-setup-cancel");
  const setupDetailEl = root.querySelector("#tip-setup-detail");
  const setupManagerEl = root.querySelector("#tip-setup-manager");
  const setupTokenEl = root.querySelector("#tip-setup-token");
  const setupChainEl = root.querySelector("#tip-setup-chain");

  let flow = null;
  let target = null;   // {slug, recipient, label}
  let quote = null;    // set once a quote has been shown
  let plan = null;     // set once channel setup has been inspected and shown

  function say(message) {
    if (statusEl) statusEl.textContent = message || "";
  }

  function reset() {
    quote = null;
    if (sendEl) sendEl.textContent = "Send Tip";
  }

  /** Show the tip panel; hide setup. */
  function showPay() {
    plan = null;
    if (payPanel) payPanel.hidden = false;
    if (setupPanel) setupPanel.hidden = true;
  }

  /** Show setup; hide the tip panel. One or the other, never both. */
  function showSetup() {
    if (payPanel) payPanel.hidden = true;
    if (setupPanel) setupPanel.hidden = false;
  }

  function close() {
    dialog.hidden = true;
    reset();
    showPay();
    say("");
  }

  function open(button) {
    target = {
      slug: button.getAttribute("data-tip-slug"),
      recipient: button.getAttribute("data-tip-recipient"),
      label: button.getAttribute("data-tip-label") || "Tips",
    };
    if (who) who.textContent = target.label;
    reset();
    showPay();
    if (fundEl && !fundEl.value) fundEl.value = DEFAULT_CHANNEL_FUNDING;
    say("");
    dialog.hidden = false;
  }

  /**
   * The tip could not be sent because there is no channel. Offer to open one.
   *
   * Called ONLY from the NO_CHANNEL branch, so reaching here means the chain
   * has already been asked and answered. Nothing is sent and no wallet prompt
   * appears until the user clicks the button this reveals.
   */
  async function offerChannelSetup(f) {
    if (!setupPanel || !quote) {
      // Older markup: keep the previous message rather than silently doing
      // nothing. A dead end is bad; a dead end with no explanation is worse.
      say(noChannelFallback());
      return;
    }
    showSetup();
    say("Checking the chain…");

    const result = await f.inspectChannel(quote, {
      amount: (fundEl && fundEl.value) || DEFAULT_CHANNEL_FUNDING,
    });
    plan = result.state === CHANNEL.READY ? result : null;

    // The disclosure, filled from the quote and the CHAIN — the token comes
    // from the manager contract, not from the server.
    if (setupManagerEl) setupManagerEl.textContent = quote.manager || "";
    if (setupChainEl) setupChainEl.textContent = `(chain ${quote.chain_id})`;
    if (setupTokenEl) setupTokenEl.textContent = result.token || "";
    if (setupDetailEl) setupDetailEl.textContent = result.message || "";

    if (openEl) {
      openEl.disabled = result.state !== CHANNEL.READY;
      openEl.textContent = result.needsApproval
        ? "Approve AXON and open channel"
        : "Open Payment Channel";
    }

    if (result.state === CHANNEL.ALREADY_OPEN && result.open) {
      // The chain disagrees with the failure that got us here. Say so plainly
      // rather than offering to open a second channel, which would revert.
      showPay();
      say("You already have a channel with this creator — try the tip again.");
      return;
    }
    say(result.state === CHANNEL.READY
      ? "Review the details, then open the channel."
      : (result.message || "This channel cannot be opened right now."));
  }

  /** The amount changed, so everything shown about it is now about a different one. */
  async function onFundAmountChanged() {
    if (!plan && !setupPanel) return;
    if (setupPanel && setupPanel.hidden) return;
    const f = await ensureFlow();
    await offerChannelSetup(f);
  }

  /** The explicit click that authorises two Mainnet transactions. */
  async function onOpenChannel() {
    const f = await ensureFlow();

    // THE PLAN MUST STILL DESCRIBE WHAT IS ON SCREEN.
    //
    // The plan carries the exact base-unit amount that will be approved and
    // deposited. If the field has moved since it was built — typed into and not
    // blurred, say — signing it would spend a number the user is not looking
    // at. Re-inspect and make them look again rather than guessing which one
    // they meant.
    if (plan && fundEl && String(fundEl.value).trim() !== plan.amountText) {
      await offerChannelSetup(f);
      say("The amount changed — check the details and open the channel again.");
      return;
    }
    if (!plan) {
      say("Check the channel details before opening it.");
      return;
    }
    if (openEl) openEl.disabled = true;
    say(plan.needsApproval
      ? "Approve AXON in your wallet…"
      : "Confirm the channel in your wallet…");

    let result;
    try {
      result = await f.openChannel(plan);
    } catch (err) {
      if (openEl) openEl.disabled = false;
      say(err.message || "The channel was not opened.");
      return;
    }

    if (result.state === CHANNEL.OPEN) {
      plan = null;
      showPay();
      // START THE TIP OVER, rather than resuming the held quote.
      //
      // A quote lives 120 seconds and opening a channel is two Mainnet
      // transactions, so the one that got us here is certainly stale — resuming
      // it would fail with "this quote expired" after the user had just paid
      // gas, which reads as the channel having not worked. Clearing it also
      // keeps the two-click rule intact: the next click quotes, the one after
      // confirms. The amount they typed is still in the field.
      reset();
      say(`${result.message} Send your tip now.`);
      return;
    }
    if (openEl) openEl.disabled = false;
    say(result.message || "The channel was not opened.");
  }

  function noChannelFallback() {
    return "You do not have a payment channel with this creator yet.";
  }

  async function ensureFlow() {
    if (!flow) flow = makeFlow(await loadEthers());
    return flow;
  }

  async function onSend() {
    if (!target) return;
    const f = await ensureFlow();

    // FIRST CLICK — quote only. Nothing is authorised and no wallet is touched.
    if (!quote) {
      say("Getting a quote…");
      try {
        quote = await f.requestQuote(target.slug, amountEl && amountEl.value);
      } catch (err) {
        quote = null;
        say(err.message || "Tipping is not available.");
        return;
      }
      say(
        `Send ${quote.total} to ${target.label}` +
        (quote.fee ? ` (${quote.amount} + ${quote.fee} fee)` : "") +
        `. Confirm to authorise in your wallet.`
      );
      if (sendEl) sendEl.textContent = "Confirm and send";
      return;
    }

    // SECOND CLICK — the explicit authorisation.
    say("Waiting for your wallet…");
    let result;
    try {
      result = await f.pay(f.confirm(quote));
    } catch (err) {
      // Thrown for an unconfirmed or expired quote. Start again.
      reset();
      say(err.message || "Could not send the tip.");
      return;
    }

    switch (result.state) {
      case STATE.SENT:
        say(result.message || "Tip sent.");
        reset();
        break;
      case STATE.UNKNOWN:
        // NOT "failed". The payment may have happened.
        say(result.message);
        reset();
        break;
      case STATE.NO_CHANNEL:
        // The one failure with an obvious next step. The quote is KEPT — the
        // user is going to want to send this exact tip once the channel exists,
        // and making them re-enter it would be the dead end all over again.
        if (sendEl) sendEl.textContent = "Send Tip";
        await offerChannelSetup(f);
        break;
      default:
        // CANCELLED, FAILED — each carries its own wording.
        say(result.message || "The tip was not sent.");
        reset();
    }
  }

  function onClick(event) {
    const button = event.target && event.target.closest
      ? event.target.closest(".tip-button")
      : null;
    if (!button) return;
    if (event.preventDefault) event.preventDefault();
    open(button);
  }

  root.addEventListener("click", onClick);
  if (sendEl) sendEl.addEventListener("click", onSend);
  if (cancelEl) cancelEl.addEventListener("click", close);
  if (openEl) openEl.addEventListener("click", onOpenChannel);
  if (setupCancelEl) setupCancelEl.addEventListener("click", close);
  // "change", not "input": re-reading the chain on every keystroke would be a
  // burst of RPC calls to say nothing new.
  if (fundEl) fundEl.addEventListener("change", onFundAmountChanged);

  return function unbind() {
    root.removeEventListener("click", onClick);
    if (sendEl) sendEl.removeEventListener("click", onSend);
    if (cancelEl) cancelEl.removeEventListener("click", close);
    if (openEl) openEl.removeEventListener("click", onOpenChannel);
    if (setupCancelEl) setupCancelEl.removeEventListener("click", close);
    if (fundEl) fundEl.removeEventListener("change", onFundAmountChanged);
  };
}

// Auto-bind in a browser; inert under node --test.
if (typeof document !== "undefined" && document.addEventListener) {
  const start = () => bindTips(document);
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
}
