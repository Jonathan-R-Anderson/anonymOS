/**
 * The recipient's own pooled-tipping view — roadmap P15 phase 5.
 *
 * WHERE THE NUMBERS COME FROM
 * ---------------------------
 * The recipient's OWN NODE, fetched by their own browser:
 *
 *     recipient's browser ──► their node /v1/pool ──► Pool.View()
 *
 * Never through this website. The site serves the page and learns nothing that
 * the page then displays — no aggregate, no channel list, no contributor count.
 * Routing it through the server would hand the platform every recipient's
 * balance without it ever holding a coin, which is the version of custody that
 * looks safe and is not.
 *
 * That is also why the node URL and token live in localStorage and are never
 * submitted to a form: a token posted to the site is a token the site can use.
 *
 * WHAT IT MAY SHOW
 * ----------------
 * Everything, because it is the recipient's private view of their own money.
 * The restraint that applies to the CONTRIBUTOR-facing tip button — no channel
 * ids, no balances — does not apply here, and pretending otherwise would just
 * hide a person's own money from them.
 *
 * The exception is vocabulary. "Available to withdraw" is what somebody wants
 * to read; "withdrawable balance across member channels net of live HTLCs" is
 * the same fact written for a protocol author.
 */

export const STATE = Object.freeze({
  /** No node configured yet. The ordinary state for someone who just enabled it. */
  NOT_CONFIGURED: "not_configured",
  LOADING: "loading",
  READY: "ready",
  /** The node did not answer. Its money is fine; the view is not available. */
  UNREACHABLE: "unreachable",
  /** The node answered, and refused the token. */
  UNAUTHORIZED: "unauthorized",
});

/**
 * Withdrawal outcomes. The SAME three the payment flow uses, deliberately:
 * a withdrawal is a transaction with the same ambiguity as a payment, and a
 * second vocabulary would invite a second, weaker interpretation of UNKNOWN.
 */
export const OUTCOME = Object.freeze({
  COMPLETED: "completed",
  REJECTED: "rejected",
  /**
   * The value is there; the contributor could not be reached to co-sign.
   *
   * A separate outcome because the two neighbouring ones both say something
   * false: REJECTED reads as "your withdrawal was refused", and UNKNOWN reads
   * as "your money might be gone". This one is neither — it is a wait.
   */
  CONTRIBUTOR_OFFLINE: "contributor_offline",
  /** May or may not have happened. NEVER shown as failure. */
  UNKNOWN: "unknown",
});

const NODE_URL_KEY = "pof.node.url";
const NODE_TOKEN_KEY = "pof.node.token";
// Where the node serves its own console. Kept with the other node settings
// because it is the same node, but it is NOT a credential: it is an address.
const NODE_CONSOLE_KEY = "pof.node.console";

/**
 * Read the node's location from local storage.
 *
 * Returns null rather than throwing when storage is unavailable (private
 * browsing, disabled cookies): a dashboard that cannot read its own settings is
 * "not configured", not broken.
 */
export function readNodeConfig(storage) {
  try {
    const url = (storage.getItem(NODE_URL_KEY) || "").trim();
    const token = (storage.getItem(NODE_TOKEN_KEY) || "").trim();
    if (!url || !token) return null;
    return { url: url.replace(/\/+$/, ""), token };
  } catch (err) {
    return null;
  }
}

export function saveNodeConfig(storage, url, token, consoleURL) {
  storage.setItem(NODE_URL_KEY, String(url || "").trim());
  storage.setItem(NODE_TOKEN_KEY, String(token || "").trim());
  if (consoleURL !== undefined) {
    storage.setItem(NODE_CONSOLE_KEY, String(consoleURL || "").trim());
  }
}

/**
 * Where this recipient's own node serves its console.
 *
 * NAVIGATION ONLY. Collecting a tip happens on the node, in the node's own
 * origin, because acceptance needs the recipient's channel key and that key
 * lives there. This page cannot do it and does not try: it can only point.
 *
 * Returns null rather than a guess when nothing is configured. Guessing a port
 * would send somebody to a page that is not their node, and a link that looks
 * right and goes nowhere is worse than an honest absence.
 */
export function readConsoleURL(storage) {
  try {
    const raw = (storage.getItem(NODE_CONSOLE_KEY) || "").trim();
    if (!raw) return null;
    // Only http(s), and only a URL that parses. A javascript: or data: value
    // here would be a link this page invited the recipient to click.
    const u = new URL(raw);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    return u.toString().replace(/\/+$/, "");
  } catch (err) {
    return null;
  }
}

export function clearNodeConfig(storage) {
  storage.removeItem(NODE_URL_KEY);
  storage.removeItem(NODE_TOKEN_KEY);
  storage.removeItem(NODE_CONSOLE_KEY);
}

/**
 * Format a wei-scale integer string for a person.
 *
 * Done with strings, never Number: an 18-decimal amount exceeds what a double
 * represents exactly, so parsing it to display it can change the number a
 * person is reading about their own money.
 */
export function formatAmount(raw, decimals = 18) {
  const digits = String(raw == null ? "0" : raw).replace(/[^0-9]/g, "") || "0";
  const padded = digits.padStart(decimals + 1, "0");
  const whole = padded.slice(0, padded.length - decimals).replace(/^0+(?=\d)/, "");
  const frac = padded.slice(padded.length - decimals).replace(/0+$/, "");
  const grouped = whole.replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  // Two decimal places is enough to see that something arrived without
  // presenting eighteen digits of noise.
  return frac ? `${grouped}.${frac.slice(0, 2).padEnd(2, "0")}` : grouped;
}

/**
 * The dashboard. `fetchImpl` and `storage` are injected so this is testable
 * without a browser and without a running node.
 */
export function createPoolDashboard({ fetchImpl, storage } = {}) {
  const doFetch = fetchImpl || (typeof fetch === "function" ? fetch : null);
  const store = storage || (typeof localStorage !== "undefined" ? localStorage : null);

  let state = STATE.NOT_CONFIGURED;
  let view = null;
  let error = null;

  function snapshot() {
    return {
      state,
      error,
      /** Human-facing aggregate, or null when there is nothing to show. */
      available: view ? formatAmount(view.withdrawable) : null,
      inFlight: view ? formatAmount(view.in_flight) : null,
      contributors: view ? view.contributors : 0,
      channels: view ? view.members : 0,
      /** Channels worth withdrawing from, richest information kept as given. */
      candidates: view && Array.isArray(view.candidates) ? view.candidates : [],
      excluded: view && Array.isArray(view.excluded) ? view.excluded : [],
    };
  }

  async function refresh() {
    const config = readNodeConfig(store);
    if (!config) {
      state = STATE.NOT_CONFIGURED;
      view = null;
      error = null;
      return snapshot();
    }

    state = STATE.LOADING;
    error = null;

    let response;
    try {
      response = await doFetch(`${config.url}/v1/pool`, {
        method: "GET",
        headers: { Authorization: `Bearer ${config.token}` },
        // No cookies to this origin. The node authorises by token, and a
        // credentialed cross-origin request would only widen what a hostile
        // page could do with the recipient's session.
        credentials: "omit",
      });
    } catch (err) {
      // A NETWORK FAILURE IS NOT A ZERO BALANCE. Showing 0 here would tell
      // somebody their tips had vanished because their laptop was offline.
      state = STATE.UNREACHABLE;
      view = null;
      error = "Could not reach your node.";
      return snapshot();
    }

    if (response.status === 401 || response.status === 403) {
      state = STATE.UNAUTHORIZED;
      view = null;
      error = "Your node refused this access token.";
      return snapshot();
    }
    if (!response.ok) {
      state = STATE.UNREACHABLE;
      view = null;
      error = "Your node could not answer.";
      return snapshot();
    }

    try {
      view = await response.json();
    } catch (err) {
      state = STATE.UNREACHABLE;
      view = null;
      error = "Your node sent an answer this page could not read.";
      return snapshot();
    }

    state = STATE.READY;
    return snapshot();
  }

  /**
   * Withdraw the value in one channel.
   *
   * The node decides the amount. This sends only the channel identifier, so a
   * tampered page cannot ask for more than the bilateral state holds — and the
   * node refuses an inflated amount anyway, which is where that rule belongs.
   *
   * NOTHING IS SUBTRACTED LOCALLY. On success the caller re-reads /v1/pool and
   * displays what the node computed. An optimistic decrement would show a
   * number no signature supports, and would be wrong in exactly the case that
   * matters — when the withdrawal did not happen.
   */
  async function withdraw(channel) {
    const config = readNodeConfig(store);
    if (!config) return { outcome: OUTCOME.REJECTED, error: "No node configured." };

    let response;
    try {
      response = await doFetch(`${config.url}/v1/pool/checkpoint`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${config.token}`,
          "Content-Type": "application/json",
        },
        credentials: "omit",
        body: JSON.stringify({ channel }),
      });
    } catch (err) {
      // THE DANGEROUS CASE. The request may have reached the node, which may
      // have co-signed and broadcast. Calling this "failed" invites a retry
      // against value that has already left.
      return {
        outcome: OUTCOME.UNKNOWN,
        error: "The withdrawal status could not be determined.",
      };
    }

    if (response.status === 401 || response.status === 403) {
      return { outcome: OUTCOME.REJECTED, error: "Your node refused this access token." };
    }
    if (response.status === 503) {
      // Nothing was sent, so nothing is in doubt. The amount comes back with
      // the refusal precisely so the recipient can be told their funds are
      // intact rather than shown a bare error.
      let amount = null;
      try {
        amount = formatAmount((await response.json()).amount);
      } catch (err) {
        amount = null;
      }
      return {
        outcome: OUTCOME.CONTRIBUTOR_OFFLINE,
        amount,
        error: amount
          ? `${amount} AXON is available, but the person who tipped you is offline right now. `
            + "They need to be online to complete this withdrawal."
          : "The person who tipped you is offline right now. "
            + "They need to be online to complete this withdrawal.",
      };
    }
    if (response.status === 409) {
      // The node itself reports an indeterminate outcome — signed but not
      // broadcast, or a transport failure mid-exchange.
      return {
        outcome: OUTCOME.UNKNOWN,
        error: "The withdrawal status could not be determined.",
      };
    }
    if (!response.ok) {
      let detail = "";
      try {
        detail = (await response.json()).error || "";
      } catch (err) {
        detail = "";
      }
      return { outcome: OUTCOME.REJECTED, error: detail || "Your node refused the withdrawal." };
    }

    let body;
    try {
      body = await response.json();
    } catch (err) {
      // A 200 whose body could not be read still means the node acted.
      return { outcome: OUTCOME.UNKNOWN, error: "The withdrawal status could not be determined." };
    }
    if (body.outcome === "UNKNOWN") {
      return { outcome: OUTCOME.UNKNOWN, error: "The withdrawal status could not be determined." };
    }
    return {
      outcome: OUTCOME.COMPLETED,
      amount: formatAmount(body.amount),
      txHash: body.tx_hash || null,
      broadcast: body.outcome === "BROADCAST",
    };
  }

  return {
    refresh,
    withdraw,
    snapshot,
    get state() {
      return state;
    },
  };
}
