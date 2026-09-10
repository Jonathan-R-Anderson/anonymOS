// Pooled tipping: the glue between the Tip button and the P8 payment client.
//
// roadmap P15, phase 2. This file contains NO payment logic and NO crypto. It
// is a sequencer: it asks the server what a tip would cost, shows the user, and
// — only after the user says yes — hands the job to tip-channel.js, which owns
// the wallet, the digests and the channel.
//
//   click Tip → amount → POST /tip/quote → SHOW → confirm → connect → tip()
//
// THREE RULES THIS FILE EXISTS TO KEEP
// -----------------------------------
// 1. NOTHING IS SENT WITHOUT AN EXPLICIT CONFIRMATION. Obtaining a quote must
//    never move money, and neither must opening the dialog. `pay()` refuses a
//    quote that has not been through `confirm()`.
//
// 2. A STALE QUOTE IS REFUSED. Between quote and confirmation the recipient may
//    have switched pooling off or unlinked their wallet, so freshness is checked
//    again at the moment of payment, not only when the quote arrived.
//
// 3. SUCCESS IS WHAT tip() SAYS, AND NOTHING ELSE. Not "the quote worked", not
//    "the wallet connected", not "we sent the request". tip-channel.js reports
//    three outcomes and the third one matters:
//
//        COMPLETED  the payment happened
//        REJECTED   it did not
//        UNKNOWN    it MAY have — never render this as either
//
// The server never sees a key, never signs, and is never told which channel to
// use: tip-channel.js derives that from the wallet it is connected to.

import { createTipChannel, OUTCOME, TipError } from "./tip-channel.js";

/** What the UI is being told. Distinct states, not a boolean. */
export const STATE = {
  IDLE: "idle",
  QUOTING: "quoting",
  QUOTED: "quoted",
  NEEDS_WALLET: "needs_wallet",
  NO_CHANNEL: "no_channel",
  AUTHORIZING: "authorizing",
  PENDING: "pending",
  SENT: "sent",
  /**
   * A volunteer is holding the tip for a creator who is offline.
   *
   * Its own state, between SENT and FAILED and equal to neither. Collapsing it
   * into SENT would tell a tipper their money had arrived when the creator has
   * agreed to nothing; collapsing it into FAILED would tell them it was lost
   * when it is safe and waiting.
   */
  QUEUED: "queued",
  FAILED: "failed",
  UNKNOWN: "unknown",
  CANCELLED: "cancelled",
};

/**
 * Opening a channel — its own states, because it is its own decision.
 *
 * A tip is free and off chain. Opening the channel that makes tips possible is
 * two Ethereum Mainnet transactions costing real gas, and collapsing the two
 * into one set of states would let a UI describe the expensive thing in the
 * language of the free one.
 */
export const CHANNEL = {
  /** Nothing asked yet. */
  IDLE: "idle",
  /** Reading the chain. No transaction, no wallet prompt. */
  CHECKING: "checking",
  /** There is already a channel; the tip flow can proceed. */
  ALREADY_OPEN: "already_open",
  /** Everything checks out. `needsApproval` says whether it is one tx or two. */
  READY: "ready",
  NEEDS_WALLET: "needs_wallet",
  WRONG_CHAIN: "wrong_chain",
  INSUFFICIENT_FUNDS: "insufficient_funds",
  /** Waiting on the approve transaction. */
  APPROVING: "approving",
  /** Waiting on openChannel. */
  OPENING: "opening",
  /** Opened and verified against the chain. */
  OPEN: "open",
  /** The user dismissed a wallet prompt. Nothing was sent. */
  CANCELLED: "cancelled",
  /** Definite failure, with a reason. */
  FAILED: "failed",
  /**
   * Broadcast, not yet mined, and we stopped waiting.
   *
   * NOT failed. The transaction may still confirm, and telling somebody it
   * failed is how one channel becomes two and the gas is paid twice.
   */
  PENDING: "pending",
};

/**
 * What a channel is funded with unless the user says otherwise, in whole AXON.
 *
 * A starting figure, not a limit: the field is editable and the number is
 * converted with the token's own `decimals()` rather than being baked into the
 * contract call. Small on purpose — this is real money on Ethereum Mainnet, and
 * a first channel should cost about as much as finding out whether you like the
 * feature.
 */
export const DEFAULT_CHANNEL_FUNDING = "1";

export class TipFlowError extends Error {
  constructor(message, state) {
    super(message);
    this.state = state;
  }
}

/**
 * @param {object} deps
 *   ethers     – the injected ethers module (same one tip-channel.js needs)
 *   fetch      – injected so tests drive it without a network
 *   now        – injected clock, so freshness is testable
 *   tipChannel – optional pre-built client (tests pass a fake)
 */
export function createTipFlow(deps = {}) {
  const fetchImpl = deps.fetch || ((...a) => globalThis.fetch(...a));
  const now = deps.now || (() => Math.floor(Date.now() / 1000));
  const tc = deps.tipChannel ||
    createTipChannel(deps.ethers || (globalThis.PoFChain && globalThis.PoFChain.ethers));

  /**
   * Ask the server what this tip would cost.
   *
   * The recipient is a SLUG in the URL path; the body carries the amount and
   * nothing else. A channel id is never sent — the server would refuse it, and
   * sending one would mean this file had an opinion about which channel to use.
   */
  async function requestQuote(slug, amount) {
    if (!slug) throw new TipFlowError("no recipient", STATE.FAILED);
    // Validated as a number, SENT as the text the user typed.
    //
    // Tips may be fractional, and JSON numbers are doubles: 0.1 does not
    // survive one intact, so a parsed Number on the wire would hand the server
    // an amount subtly unlike the one on screen — and the server scales it by
    // 10^18 into a state somebody signs. The text goes through untouched and is
    // parsed once, exactly, as a Decimal.
    const text = String(amount == null ? "" : amount).trim();
    const parsed = Number(text);
    if (!text || !Number.isFinite(parsed) || parsed <= 0) {
      throw new TipFlowError("Enter an amount greater than zero.", STATE.IDLE);
    }
    const response = await fetchImpl(
      `/profile/${encodeURIComponent(slug)}/tip/quote`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        // ONLY the amount. Not a channel, not a nonce, not a route.
        body: JSON.stringify({ amount: text }),
      },
    );
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new TipFlowError(body.message || "Tipping is not available.", STATE.FAILED);
    }
    // `confirmed` is deliberately absent here. A quote arrives unconfirmed and
    // must pass through confirm() before pay() will touch it.
    return { ...body, confirmed: false };
  }

  /** The user has read the quote and said yes. This authorises nothing on its own. */
  function confirm(quote) {
    if (!quote) throw new TipFlowError("no quote", STATE.FAILED);
    return { ...quote, confirmed: true };
  }

  function isFresh(quote, at = now()) {
    return Boolean(quote) && Number(quote.expires_at) > at;
  }

  /**
   * Perform the payment. Requires a CONFIRMED, FRESH quote.
   *
   * Every branch that is not an unambiguous success returns a non-success
   * state. There is no path here that reports "sent" on anything other than
   * OUTCOME.COMPLETED.
   */
  async function pay(quote, options = {}) {
    if (!quote || !quote.confirmed) {
      // The whole point of the dialog. A caller that skipped confirmation is a
      // bug, not a fast path.
      throw new TipFlowError("The tip was not confirmed.", STATE.CANCELLED);
    }
    if (!isFresh(quote)) {
      throw new TipFlowError(
        "This quote expired. Request a new one.", STATE.IDLE);
    }

    let session;
    try {
      session = await tc.connect(options.provider);
    } catch (err) {
      // Includes the user closing or rejecting the wallet prompt. NOT a
      // failure of the payment: nothing was sent.
      return { state: STATE.CANCELLED, message: walletMessage(err) };
    }

    let result;
    try {
      result = await tc.tip(session, {
        endpoint: quote.endpoint,
        recipient: quote.recipient,
        // BASE UNITS. quote.amount is the human figure and must never reach
        // a signed state: the two differ by 10^18.
        amount: quote.amount_base,
        manager: quote.manager,
      });
    } catch (err) {
      if (err instanceof TipError && err.code === "no_channel") {
        return { state: STATE.NO_CHANNEL, message: noChannelMessage() };
      }
      // THE MAILBOX FALLBACK, and the ONLY code that may reach it.
      //
      // `recipient_unreachable` is raised at exactly one place: the initial
      // STATE_REQUEST, which proposes nothing. Reaching it proves no signature
      // exists and the creator cannot have acted, so handing the tip to a
      // volunteer cannot duplicate anything.
      //
      // Every other failure — including a transport failure after the proposal
      // was sent — falls through to UNKNOWN below and is NEVER queued. Queuing
      // an ambiguous payment is how one tip becomes two.
      if (err instanceof TipError && err.code === "recipient_unreachable") {
        return await queueWithVolunteer(session, quote);
      }
      // A throw is not a rejection. We do not know what happened.
      return { state: STATE.UNKNOWN, message: unknownMessage() };
    }

    // SUCCESS IS tip()'s WORD. Nothing else in this file may produce SENT.
    switch (result.outcome) {
      case OUTCOME.COMPLETED:
        return { state: STATE.SENT, message: "Tip sent." };
      case OUTCOME.QUEUED:
        // Deliberately not SENT. The creator has agreed to nothing yet.
        return {
          state: STATE.QUEUED,
          message: "This creator is offline. Your tip is waiting for them and "
            + "completes when they next open their wallet.",
        };
      case OUTCOME.REJECTED:
        return { state: STATE.FAILED, message: "The creator's node declined the tip." };
      default:
        return { state: STATE.UNKNOWN, message: unknownMessage() };
    }
  }

  /**
   * Hand the tip to the creator's volunteer, when they have one.
   *
   * Only ever called from the one branch that has established the creator's own
   * node is unreachable AND that nothing was proposed. It reports QUEUED on
   * success and never SENT — the creator has agreed to nothing yet.
   */
  async function queueWithVolunteer(session, quote) {
    const volunteer = quote.volunteer_endpoint;
    if (!volunteer) {
      // No mailbox configured. The creator is simply unreachable, which is a
      // true statement and not a failure of this payment.
      return {
        state: STATE.UNKNOWN,
        message: "The creator's node did not answer and they have no mailbox. "
          + "Nothing was sent — try again later.",
      };
    }
    // TWO OPERATIONS, TWO try BLOCKS, deliberately.
    //
    // They were one, and a failure to BUILD the proposal — most often no
    // channel on chain between these two wallets — was reported as "the mailbox
    // refused the message". That names the wrong component: it sends somebody
    // to inspect a volunteer that is working perfectly, and hides the real
    // problem, which is that there is no payment path to queue anything on.
    // WHAT THE PREVIOUS TIP LEFT BEHIND.
    //
    // proposeEnvelope falls back to the chain when given no base, which is
    // right for a first tip and wrong for a second: in mailbox mode the chain
    // has not moved, so tip 2 would reuse tip 1's update number and the two
    // would collide at the recipient. This asks the volunteer what this wallet
    // has already had accepted and continues from there.
    //
    // null is an ordinary answer — a first tip, or a volunteer that could not
    // be reached — and means "build on the chain", which is what a first tip
    // should do anyway.
    let base;
    try {
      base = await tc.recoverBase(session, {
        volunteer,
        nodeId: quote.volunteer_node_id,
        recipient: quote.recipient,
        manager: quote.manager,
      });
    } catch (err) {
      // NOTHING WAS SENT. Not queued-and-hope: if this wallet has already had a
      // tip accepted and we cannot find out, the proposal we would build sits
      // at an update number the recipient already holds and can never be
      // accepted. Telling somebody their tip is waiting would be false.
      return {
        state: STATE.FAILED,
        message: "Your previous tips to this creator could not be checked, so "
          + "this one was not sent. Nothing was charged and nothing is lost — "
          + "try again shortly.",
      };
    }

    let envelope;
    try {
      envelope = await tc.proposeEnvelope(session, {
        endpoint: quote.endpoint,
        recipient: quote.recipient,
        amount: quote.amount_base,
        manager: quote.manager,
        base,
      });
    } catch (err) {
      // Nothing was sent anywhere. The volunteer has not been contacted and is
      // not implicated.
      //
      // "No channel" is singled out because it is the one cause with an obvious
      // remedy, and a POOLED tip hits it exactly as a direct one does — the pool
      // is how the recipient aggregates what arrives, not a different payment
      // path, so it needs the same bilateral channel underneath. Reporting it as
      // NO_CHANNEL rather than FAILED is what lets one setup flow serve both;
      // otherwise a contributor to an offline creator gets the correct sentence
      // ("set one up first") and still no way to do it.
      const code = err && err.code;
      if (code === "no_channel" || code === "not_open") {
        return { state: STATE.NO_CHANNEL, message: proposalMessage(err) };
      }
      return { state: STATE.FAILED, message: proposalMessage(err) };
    }

    try {
      await tc.deliverToMailbox(volunteer, quote.recipient, envelope);
    } catch (err) {
      // A mailbox that refused, was unreachable, or was http:// is a failure to
      // QUEUE. Nothing was paid and nothing is in doubt, so this is reported
      // plainly rather than as UNKNOWN.
      return { state: STATE.FAILED, message: volunteerMessage(err) };
    }
    return {
      state: STATE.QUEUED,
      // No form of the word "complete" anywhere, even in a future clause: a
      // reader skimming for the outcome should not find it next to their tip.
      message: "Tip queued for delivery. The creator is offline — they still "
        + "need to collect and accept it, which happens when they next open "
        + "their wallet.",
    };
  }

  /**
   * Why a proposal could not be built. Never mentions the mailbox.
   *
   * `no_channel` is the common one and it is NOT a transport problem: the two
   * wallets have no bilateral channel on chain, so there is no state to
   * advance and nothing that could be queued. It is not UNKNOWN either —
   * nothing was attempted — and certainly not QUEUED.
   */
  function proposalMessage(err) {
    switch (err && err.code) {
      case "no_channel":
      case "not_open":
        return "You have no tipping channel with this creator yet, so there was "
          + "nothing to send. Set one up first.";
      case "wrong_parties":
        return "The channel on record is between different wallets. Nothing was sent.";
      case "not_conserved":
        return "That amount does not add up against the channel. Nothing was sent.";
      case "stale_base":
        return "This tip was built on an out-of-date state. Try again.";
      default:
        return "The tip could not be prepared, so nothing was sent.";
    }
  }

  function volunteerMessage(err) {
    switch (err && err.code) {
      case "insecure_endpoint":
        return "That creator's mailbox is not served securely, so nothing was sent.";
      case "volunteer_unreachable":
        return "The creator's mailbox could not be reached. Nothing was sent.";
      case "volunteer_not_serving":
        return "That mailbox does not carry tips for this creator. Nothing was sent.";
      default:
        return "The mailbox refused the message. Nothing was sent.";
    }
  }

  function walletMessage(err) {
    if (err && err.code === "no_wallet") {
      return "No wallet found in this browser.";
    }
    return "Wallet authorization was cancelled — nothing was sent.";
  }

  function noChannelMessage() {
    return "You do not have a payment channel with this creator yet.";
  }

  // ---- channel setup ---------------------------------------------------------
  //
  // The gap this closes: tip-channel.js has been able to open a channel since
  // P8-b, and nothing called it. A tipper with no channel was told they had no
  // channel and given nowhere to go, which made every other part of the tipping
  // system unreachable for anybody who had not opened one by hand.
  //
  // Two functions rather than one, deliberately:
  //
  //   inspect()  reads the chain and decides what would need to happen
  //   open()     does it, and only after the user has seen the above
  //
  // Nothing in inspect() sends a transaction or costs gas, so a UI can call it
  // to DECIDE WHAT TO SHOW without committing the user to anything.

  /** Whole coins → base units, exactly. No floats: 0.1 is not 0.1 in binary. */
  function toBaseUnits(amount, decimals) {
    const text = String(amount).trim();
    if (!/^\d+(\.\d+)?$/.test(text)) {
      throw new TipFlowError("Enter an amount greater than zero.", CHANNEL.FAILED);
    }
    const [whole, frac = ""] = text.split(".");
    if (frac.length > decimals) {
      throw new TipFlowError(
        `That amount has more than ${decimals} decimal places.`, CHANNEL.FAILED);
    }
    const scaled = BigInt(whole + frac.padEnd(decimals, "0"));
    if (scaled <= 0n) {
      throw new TipFlowError("Enter an amount greater than zero.", CHANNEL.FAILED);
    }
    return scaled;
  }

  /** Base units → a whole-coin string a person can read. */
  function fromBaseUnits(value, decimals) {
    const s = BigInt(value).toString().padStart(decimals + 1, "0");
    const whole = s.slice(0, s.length - decimals);
    const frac = s.slice(s.length - decimals).replace(/0+$/, "");
    return frac ? `${whole}.${frac}` : whole;
  }

  /**
   * What opening a channel with this recipient would involve. READ ONLY.
   *
   * The token is asked of the MANAGER, never taken from the quote: approving a
   * token is granting a contract power over that balance, and the only address
   * whose answer about "which token will you pull?" cannot be wrong is the
   * contract that will do the pulling.
   */
  async function inspectChannel(quote, options = {}) {
    if (!quote || !quote.manager) {
      return {
        state: CHANNEL.FAILED,
        message: "This site has no payment contract configured, so a channel "
          + "cannot be opened. Nothing was sent.",
      };
    }

    let session;
    try {
      session = options.session || await tc.connect(options.provider);
    } catch (err) {
      return {
        state: CHANNEL.NEEDS_WALLET,
        message: (err && err.code === "no_wallet")
          ? "No wallet found in this browser. Install one to open a channel."
          : "Wallet connection was cancelled — nothing was sent.",
      };
    }

    // The chain the quote was issued for, not whichever one the wallet happens
    // to be on. A channel opened on the wrong chain is real money on a contract
    // this site will never read.
    const want = BigInt(quote.chain_id);
    if (BigInt(session.chainId) !== want) {
      return {
        state: CHANNEL.WRONG_CHAIN,
        session,
        message: `Your wallet is on chain ${session.chainId}. Switch it to `
          + `Ethereum Mainnet (chain ${want}) to open this channel.`,
      };
    }

    let token, decimals, snapshot;
    try {
      token = await tc.managerToken(session, { manager: quote.manager });
      decimals = await tc.tokenDecimals(session, { token });
      snapshot = await tc.channelSnapshot(session, {
        manager: quote.manager,
        id: tc.deriveChannelId(session.address, quote.recipient),
        recipient: quote.recipient,
      });
    } catch (err) {
      return {
        state: CHANNEL.FAILED,
        session,
        message: chainReadMessage(err),
      };
    }

    if (snapshot.exists) {
      // Includes Closing and Settled. Those are not "open for tips", but they
      // are equally not "open a second one" — openChannel reverts on any status
      // that is not None, so offering setup here would send a doomed transaction.
      return {
        state: CHANNEL.ALREADY_OPEN,
        session, token, decimals, snapshot,
        open: snapshot.open,
        message: snapshot.open
          ? "You already have a channel with this creator."
          : "Your channel with this creator is closing or settled, so no new "
            + "one can be opened with them.",
      };
    }

    let amountBase;
    try {
      amountBase = toBaseUnits(options.amount ?? DEFAULT_CHANNEL_FUNDING, decimals);
    } catch (err) {
      return { state: CHANNEL.FAILED, session, token, decimals, message: err.message };
    }

    let balance, allowance;
    try {
      balance = await tc.tokenBalance(session, { token, owner: session.address });
      allowance = await tc.tokenAllowance(session, {
        token, owner: session.address, spender: quote.manager,
      });
    } catch (err) {
      return { state: CHANNEL.FAILED, session, token, decimals, message: chainReadMessage(err) };
    }

    const plan = {
      session, token, decimals, amountBase,
      manager: quote.manager,
      recipient: quote.recipient,
      chainId: want,
      balance, allowance,
      needsApproval: allowance < amountBase,
      amountText: fromBaseUnits(amountBase, decimals),
      balanceText: fromBaseUnits(balance, decimals),
    };

    if (balance < amountBase) {
      return {
        ...plan,
        state: CHANNEL.INSUFFICIENT_FUNDS,
        message: `You need ${plan.amountText} AXON to fund this channel and you `
          + `have ${plan.balanceText}. Nothing was sent.`,
      };
    }

    return {
      ...plan,
      state: CHANNEL.READY,
      message: plan.needsApproval
        ? `Two wallet confirmations: approve ${plan.amountText} AXON, then open `
          + `the channel.`
        : `One wallet confirmation: ${plan.amountText} AXON is already approved, `
          + `so only the channel needs opening.`,
    };
  }

  /**
   * Open it. Requires a plan from inspectChannel that reached READY.
   *
   * Refuses anything else rather than re-deriving one, for the same reason
   * pay() refuses an unconfirmed quote: the user agreed to what they were
   * shown, and re-deriving here could send a transaction for a different
   * amount than the one on screen.
   */
  async function openChannel(plan, options = {}) {
    if (!plan || plan.state !== CHANNEL.READY) {
      throw new TipFlowError(
        "The channel was not confirmed.", CHANNEL.CANCELLED);
    }
    const { session, token, manager, recipient, amountBase } = plan;
    const receipt = (hash) => tc.awaitReceipt(session, hash, options.receipt || {});

    if (plan.needsApproval) {
      let approveTx;
      try {
        approveTx = await tc.approveToken(session, {
          token, spender: manager, amount: amountBase,
        });
      } catch (err) {
        return { ...walletFailure(err, "approval"), stage: "approve" };
      }
      try {
        await receipt(approveTx);
      } catch (err) {
        return { ...receiptFailure(err, "approval", approveTx), stage: "approve" };
      }

      // RE-READ, rather than assume the receipt means what we wanted. A token
      // may cap, ignore or partially apply an approval; the number that governs
      // openChannel is the one the token reports now.
      let allowance;
      try {
        allowance = await tc.tokenAllowance(session, {
          token, owner: session.address, spender: manager,
        });
      } catch (err) {
        return {
          state: CHANNEL.FAILED, stage: "approve", approveTx,
          message: chainReadMessage(err),
        };
      }
      if (allowance < amountBase) {
        return {
          state: CHANNEL.FAILED, stage: "approve", approveTx,
          message: "The approval went through but the allowance is still too "
            + "low to fund this channel. No channel was opened.",
        };
      }
    }

    let openTx;
    try {
      openTx = await tc.openChannelTx(session, {
        recipient, deposit: amountBase, manager,
      });
    } catch (err) {
      return { ...walletFailure(err, "channel"), stage: "open" };
    }
    try {
      await receipt(openTx);
    } catch (err) {
      return { ...receiptFailure(err, "channel", openTx), stage: "open" };
    }

    // VERIFY AGAINST THE CHAIN. A mined, non-reverted transaction is good
    // evidence and not the fact itself; the fact is what channels(id) says.
    let snapshot;
    try {
      snapshot = await tc.channelSnapshot(session, {
        manager, id: tc.deriveChannelId(session.address, recipient), recipient,
      });
    } catch (err) {
      return {
        state: CHANNEL.FAILED, stage: "verify", openTx,
        message: chainReadMessage(err),
      };
    }
    if (!snapshot.exists || !snapshot.open) {
      return {
        state: CHANNEL.FAILED, stage: "verify", openTx,
        message: "The transaction was mined but the chain does not show an open "
          + "channel. Do not send it again until you have checked.",
      };
    }
    if (!snapshot.partiesMatch) {
      return {
        state: CHANNEL.FAILED, stage: "verify", openTx, snapshot,
        message: "A channel was opened but it names different wallets. Do not "
          + "tip on it.",
      };
    }
    if (snapshot.mine < amountBase) {
      return {
        state: CHANNEL.FAILED, stage: "verify", openTx, snapshot,
        message: `The channel opened with ${fromBaseUnits(snapshot.mine, plan.decimals)} `
          + `AXON rather than the ${plan.amountText} requested.`,
      };
    }

    return {
      state: CHANNEL.OPEN,
      openTx, snapshot,
      channel: snapshot.id,
      funded: snapshot.mine,
      fundedText: fromBaseUnits(snapshot.mine, plan.decimals),
      message: `Channel open with ${fromBaseUnits(snapshot.mine, plan.decimals)} `
        + `AXON. Tips from here are off chain and cost no gas.`,
    };
  }

  /** A wallet prompt that did not produce a transaction. */
  function walletFailure(err, what) {
    if (err && (err.code === 4001 || err.code === "ACTION_REJECTED")) {
      return {
        state: CHANNEL.CANCELLED,
        message: `You dismissed the ${what} in your wallet. Nothing was sent.`,
      };
    }
    if (err && err.code === "wallet_changed") {
      return {
        state: CHANNEL.FAILED,
        message: "Your wallet switched accounts. Nothing was sent.",
      };
    }
    if (err && err.code === "chain_changed") {
      return {
        state: CHANNEL.WRONG_CHAIN,
        message: "Your wallet switched networks. Nothing was sent.",
      };
    }
    return {
      state: CHANNEL.FAILED,
      message: `Your wallet refused the ${what}. Nothing was sent.`,
    };
  }

  /** A transaction that WAS broadcast. Reverted and pending are not the same. */
  function receiptFailure(err, what, txHash) {
    if (err && err.code === "reverted") {
      return {
        state: CHANNEL.FAILED, txHash,
        message: `The ${what} transaction was mined but reverted. Gas was spent `
          + `and nothing else happened.`,
      };
    }
    if (err && err.code === "pending") {
      return {
        state: CHANNEL.PENDING, txHash,
        message: `The ${what} transaction has not been mined yet. It may still `
          + `confirm — check it before trying again.`,
      };
    }
    return {
      state: CHANNEL.PENDING, txHash,
      message: `The ${what} transaction was sent but its result could not be `
        + `read. Check it before trying again.`,
    };
  }

  function chainReadMessage(err) {
    switch (err && err.code) {
      case "not_a_manager":
        return "The configured payment contract does not look like a channel "
          + "manager. Nothing was sent.";
      case "token_unreadable":
        return "The AXON token contract did not answer. Nothing was sent.";
      case "no_channel":
        return "There is no channel between these wallets yet.";
      default:
        return "The chain could not be read, so nothing was sent.";
    }
  }

  function unknownMessage() {
    // Deliberately not "failed". The payment may have happened, and telling
    // somebody it failed invites them to pay twice.
    return "The result is not known yet. Check before sending again.";
  }

  return {
    requestQuote, confirm, isFresh, pay, STATE,
    // channel setup
    inspectChannel, openChannel, CHANNEL,
    toBaseUnits, fromBaseUnits,
    DEFAULT_CHANNEL_FUNDING,
  };
}
