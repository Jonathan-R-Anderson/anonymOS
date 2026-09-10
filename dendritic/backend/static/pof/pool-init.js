/**
 * Binds the recipient's pooled-tipping dashboard to the settings page — P15.
 *
 * All decisions live in pool-dashboard.js; this file only moves values between
 * that module and the DOM. Split for the same reason tip-init.js is split from
 * tip-flow.js: the logic worth testing should not need a browser to run.
 *
 * The one rule this file enforces on its own: THE NODE CREDENTIALS NEVER TOUCH
 * A FORM. The inputs below live outside the settings <form> and are read
 * directly into local storage, so a submit cannot carry them to the server.
 */

import { createPoolDashboard, saveNodeConfig, clearNodeConfig, readNodeConfig,
  readConsoleURL, STATE } from "./pool-dashboard.js";

const MESSAGE = {
  [STATE.NOT_CONFIGURED]:
    "Connect your node to see what you have received.",
  [STATE.LOADING]: "Checking with your node…",
  [STATE.UNREACHABLE]:
    "Could not reach your node. Your tips are safe — this page just cannot read them right now.",
  [STATE.UNAUTHORIZED]:
    "Your node refused this access key. Check the key and try again.",
};

function bind() {
  const root = document.getElementById("pool-dashboard");
  if (!root) return;

  // Only shown once pooled tipping is switched on: a dashboard for a feature
  // somebody has not enabled is clutter that looks like a bug.
  const toggle = document.getElementById("pool_enabled");
  const sync = () => { root.hidden = !(toggle && toggle.checked); };
  if (toggle) toggle.addEventListener("change", sync);
  sync();

  const dash = createPoolDashboard({});
  const el = (id) => document.getElementById(id);
  const status = el("pool-status");
  const form = el("pool-connect-form");

  function paint(snap) {
    // A number is shown ONLY in the READY state. Every failure leaves the dash
    // reading "—", because a stale or zeroed figure would tell somebody
    // something false about their own money.
    const ready = snap.state === STATE.READY;
    el("pool-available").textContent = ready ? snap.available : "—";
    el("pool-inflight").textContent = ready ? snap.inFlight : "—";
    el("pool-contributors").textContent = ready ? String(snap.contributors) : "—";

    // Withdrawing is only offered when the node says there is something to
    // withdraw. A live button over an unknown balance would send a request the
    // node must then refuse.
    const btn = document.getElementById("pool-withdraw");
    if (btn) btn.disabled = !(ready && (snap.candidates || []).length);

    if (ready) {
      status.textContent = snap.channels
        ? `From ${snap.channels} channel${snap.channels === 1 ? "" : "s"}.`
        : "Nothing has arrived yet.";
      status.className = "small mb-2 text-muted";
      return;
    }
    status.textContent = MESSAGE[snap.state] || snap.error || "";
    status.className = "small mb-2 " +
      (snap.state === STATE.NOT_CONFIGURED ? "text-muted" : "text-danger");
  }

  async function refresh() {
    paint({ state: STATE.LOADING });
    paint(await dash.refresh());
  }

  el("pool-refresh").addEventListener("click", refresh);

  const withdrawBtn = el("pool-withdraw");

  withdrawBtn.addEventListener("click", async () => {
    const snap = dash.snapshot();
    const candidates = snap.candidates || [];
    if (!candidates.length) return;

    // EXPLICIT CONFIRMATION, naming the amount. A withdrawal is a chain
    // transaction that costs gas and cannot be undone, so it does not happen
    // on a single click.
    const total = snap.available;
    const many = candidates.length > 1;
    const ok = window.confirm(
      `Withdraw ${total} AXON?` +
      (many
        ? `\n\nThis sends ${candidates.length} separate transactions — one per person tipping you. Each is signed with them individually.`
        : "\n\nThis sends one transaction."));
    if (!ok) return;

    withdrawBtn.disabled = true;
    let done = 0;
    let unknown = 0;
    let refused = 0;
    let offline = 0;
    let offlineAmount = null;

    // One call per channel: a checkpoint is bilateral and the contract takes a
    // single channel id. The loop is here, not in the protocol.
    for (const cand of candidates) {
      const result = await dash.withdraw(cand.channel);
      if (result.outcome === "completed") done += 1;
      else if (result.outcome === "unknown") unknown += 1;
      else if (result.outcome === "contributor_offline") {
        offline += 1;
        offlineAmount = result.amount || offlineAmount;
      } else refused += 1;

      status.textContent =
        `Withdrawing… ${done + unknown + refused + offline} of ${candidates.length}.`;
      status.className = "small mb-2 text-muted";
    }

    if (unknown) {
      // NEVER "failed". The transaction may have been broadcast, and a retry
      // could withdraw against value that has already left.
      status.textContent =
        `${unknown} withdrawal${unknown === 1 ? "" : "s"} could not be confirmed. ` +
        "Do not try again yet — refresh in a minute to see the settled position.";
      status.className = "small mb-2 text-warning";
    } else if (offline) {
      // NOT a failure and NOT a loss. The value is untouched and the
      // withdrawal simply needs the other person online. Worded so it reads
      // as a wait rather than as anyone having done something wrong.
      const who = offline === 1 ? "one person" : `${offline} people`;
      status.textContent =
        (offlineAmount ? `${offlineAmount} AXON is available. ` : "Your funds are available. ") +
        `${who} who tipped you ${offline === 1 ? "is" : "are"} offline right now, ` +
        "and they need to be online to complete the withdrawal. Nothing has been lost — try again later.";
      status.className = "small mb-2 text-info";
    } else if (refused && !done) {
      status.textContent = "The withdrawal was refused by your node.";
      status.className = "small mb-2 text-danger";
    }

    // The node is authoritative for what is left. Nothing was subtracted here.
    const snapAfter = await dash.refresh();
    if (!unknown) paint(snapAfter);
    withdrawBtn.disabled = !(snapAfter.candidates || []).length;
  });

  el("pool-connect").addEventListener("click", () => {
    form.hidden = !form.hidden;
    const existing = readNodeConfig(localStorage);
    if (existing) el("pool-node-url").value = existing.url;
    const consoleEl = el("pool-node-console");
    if (consoleEl) consoleEl.value = readConsoleURL(localStorage) || "";
  });

  el("pool-node-save").addEventListener("click", async () => {
    const consoleEl = el("pool-node-console");
    saveNodeConfig(localStorage, el("pool-node-url").value, el("pool-node-token").value,
      consoleEl ? consoleEl.value : undefined);
    // Cleared immediately: leaving a key sitting in a field is how it ends up
    // in a screenshot or a password manager's form-fill for the wrong origin.
    el("pool-node-token").value = "";
    form.hidden = true;
    await refresh();
  });

  el("pool-node-forget").addEventListener("click", async () => {
    clearNodeConfig(localStorage);
    el("pool-node-url").value = "";
    el("pool-node-token").value = "";
    await refresh();
  });

  // ---- tips waiting (P15) --------------------------------------------------
  //
  // A signpost, not a collector. The dashboard above reads the node's own view
  // of what it already holds; this points at the node's console, which is the
  // only place a tip can actually be accepted.
  const waiting = el("pool-waiting");
  if (waiting) bindWaiting(waiting, dash);

  refresh();
}

function bindWaiting(root, dash) {
  const statusEl = document.getElementById("pool-waiting-status");
  const detail = document.getElementById("pool-waiting-detail");
  const confirm = document.getElementById("pool-waiting-confirm");
  const volunteer = root.dataset.volunteer || "";

  // WHY THIS PAGE NO LONGER COLLECTS
  // --------------------------------
  // Accepting a tip needs the recipient's channel key, and that key lives in
  // their node — which is the whole point of mailbox mode, since it lets
  // somebody be tipped while their browser is closed. The node exposes that
  // authority on a loopback, spending-capable operator API, and this page is a
  // different origin, so it cannot read it and must not be given a credential
  // that could.
  //
  // So collection happens where the authority is: in the node's own console,
  // which serves its own pages and calls the payment code in-process. This
  // panel's whole job is to point somebody at it.
  //
  // The alternative was a Syndichan-side proxy holding each recipient's node
  // token. It would have given the website a credential that can settle and
  // spend on somebody else's node, and it could not have worked anyway: the
  // operator API is loopback-bound on the RECIPIENT's machine, and Syndichan's
  // server would have been dialling its own.
  detail.hidden = true;
  confirm.hidden = true;

  function say(text, cls) {
    statusEl.textContent = text;
    statusEl.className = "small " + (cls || "text-muted");
  }

  const console_ = readConsoleURL(localStorage);
  if (!volunteer) {
    say("No mailbox is configured, so nothing can be waiting.", "text-muted");
    return;
  }
  if (!console_) {
    // FAIL CLOSED. No guessed port, no link to somewhere that might not be
    // this person's node. Nothing is wrong with their tips; this page simply
    // does not know where to send them.
    say("Tips are collected in your own node's console, and this page does not "
      + "know its address yet. Add it under \u201cConnect your node\u201d above. "
      + "Nothing is lost in the meantime \u2014 anything sent to you stays in your "
      + "mailbox until you accept it.", "text-muted");
    return;
  }

  const link = document.createElement("a");
  link.href = console_ + "/#tips";
  link.rel = "noopener noreferrer";
  link.target = "_blank";
  link.className = "btn btn-sm btn-outline-primary";
  link.id = "pool-waiting-console";
  link.textContent = "Open your tips";

  statusEl.textContent = "Tips are reviewed and accepted in your own node's "
    + "console, because only your node holds the key that can accept them. "
    + "This page cannot see or accept them on your behalf.";
  statusEl.className = "small text-body";
  statusEl.after(link);
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", bind);
} else {
  bind();
}
