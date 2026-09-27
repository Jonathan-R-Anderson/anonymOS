// The tipper's side of a payment channel, in the browser — roadmap P8.
//
// THE RULE THAT SHAPES ALL OF IT
// ------------------------------
// This code MUST construct every digest it signs. It must never sign a blob a
// server handed it.
//
// A page that signs whatever it is given has handed the user's wallet to
// whoever served the page: one request, one "please approve", and the whole
// channel balance moves. So the encoding is reimplemented here — a third time,
// after Solidity and Go — and each of the three is checked against the same
// frozen vectors. That duplication is the price of not being a signing oracle,
// and it is worth paying.
//
// It follows that this file trusts NOTHING it is told about money. The node is
// asked for the current signed state; what comes back is re-derived, re-hashed,
// and compared against what this code expected before a signature is requested.
// A state that does not produce the digest this code computed is refused.
//
// WHAT THIS IS NOT
// ----------------
// Not a router. A routed tip is one signed state on one channel, exactly like a
// direct one — whether it carries a lock is the node's business, not the
// browser's. Nothing here forwards, holds a preimage, or knows a route.
//
// Not a source of truth. The chain says what a channel is worth; the signed
// state says what the parties agreed; this says neither. It is a signing client
// with enough understanding to refuse.
//
// USAGE
// -----
//	import { createTipChannel } from "./tip-channel.js";
//	const tc = createTipChannel(window.PoFChain.ethers);
//
// The ethers dependency is injected rather than imported so the browser reuses
// the bundle already served on the page (chain-bundle.js) instead of shipping a
// second copy of a crypto library, and so tests can drive the same code under
// node. Nothing else is injected: the encoding is the point of the file.

// ---- 0. wiring --------------------------------------------------------------

/** Message types. The closed set from doc/channel-payment-protocol.md. */
export const MSG = {
  HELLO: "HELLO",
  CHANNEL_ANNOUNCE: "CHANNEL_ANNOUNCE",
  STATE_PROPOSE: "STATE_PROPOSE",
  STATE_ACCEPT: "STATE_ACCEPT",
  STATE_REJECT: "STATE_REJECT",
  STATE_REQUEST: "STATE_REQUEST",
  STATE_RESPONSE: "STATE_RESPONSE",
  CONFLICT: "CONFLICT",
  CLOSING: "CLOSING",
  ERROR: "ERROR",
};

export const PROTOCOL_VERSION = 1;

/**
 * Outcomes of a tip. Three, not two.
 *
 * UNKNOWN is not a failure and must never be rendered as one. It means the
 * exchange did not finish and the payment MAY have happened — the same
 * distinction the node draws, for the same reason: a browser that reported
 * "failed" on a dropped connection would invite a user to pay twice.
 */
export const OUTCOME = {
  COMPLETED: "completed",
  REJECTED: "rejected",
  UNKNOWN: "unknown",
  /**
   * A volunteer is holding the message for a creator who is not online.
   *
   * NOT a fourth kind of success. Nothing has been agreed: the creator has not
   * seen the proposal, has not countersigned it, and their balance has not
   * moved. It exists as its own outcome precisely so that it cannot be reported
   * as COMPLETED — "your tip was sent" must never mean "somebody wrote it
   * down" — and equally so that it is not reported as a failure, because the
   * message is safe and will complete when the creator returns.
   */
  QUEUED: "queued",
};

/**
 * Transition kinds this client can propose.
 *
 * The values are the protocol's, not this file's. They travel verbatim in a
 * STATE_PROPOSE, so inventing a friendlier spelling here would simply be a
 * message the node cannot read.
 */
export const KIND = {
  PAY: "PAY",
  LOCK_ADD: "LOCK_ADD",
};

export class TipError extends Error {
  constructor(message, code) {
    super(message);
    this.name = "TipError";
    this.code = code || "tip_error";
  }
}

export function createTipChannel(ethers, options = {}) {
  if (!ethers || typeof ethers.keccak256 !== "function") {
    throw new TipError("tip-channel needs an ethers v6 module", "no_ethers");
  }

  const abi = ethers.AbiCoder.defaultAbiCoder();
  const fetchImpl = options.fetch || ((...a) => globalThis.fetch(...a));
  const randomBytes = options.randomBytes || defaultRandomBytes;

  // ---- 1. the digest ---------------------------------------------------------

  /** Operation domains, matching ChannelManagerV2's OP_* constants. */
  const OP_STATE = 1;
  const OP_COOP_CLOSE = 2;
  const OP_CHECKPOINT = 3;
  //
  // Mirrors ChannelManagerV2 exactly. The Solidity is the authority; this is the
  // thing being checked against it.

  /**
   * channelId(a, b) — keccak256(abi.encode(lower, higher)).
   *
   * The addresses are SORTED, which is where the trap lives: party A is the
   * numerically lower address and has nothing to do with who is paying. A
   * tipper is party A for roughly half of all recipients, and code that assumes
   * "I am paying, so I am B" is right half the time — the worst possible rate,
   * because it works in testing.
   */
  function deriveChannelId(a, b) {
    const [lo, hi] = sortParties(a, b);
    return ethers.keccak256(abi.encode(["address", "address"], [lo, hi]));
  }

  /** Returns [lower, higher]. The only place party order is decided. */
  function sortParties(a, b) {
    const x = ethers.getAddress(a);
    const y = ethers.getAddress(b);
    return BigInt(x) < BigInt(y) ? [x, y] : [y, x];
  }

  /** True when `self` is party A of this channel. */
  function isPartyA(self, other) {
    return sortParties(self, other)[0] === ethers.getAddress(self);
  }

  /**
   * htlcRoot(locks) — keccak256 over the packed, id-sorted locks.
   *
   * Empty is bytes32(0) rather than the hash of nothing: the contract says so,
   * and a channel with no locks is the ordinary case.
   */
  function htlcRoot(locks) {
    if (!locks || locks.length === 0) return ZERO32;
    const sorted = [...locks].sort((p, q) => (BigInt(p.id) < BigInt(q.id) ? -1 : 1));
    let buf = "0x";
    for (let i = 0; i < sorted.length; i++) {
      if (i > 0 && BigInt(sorted[i - 1].id) >= BigInt(sorted[i].id)) {
        throw new TipError("duplicate lock id", "locks_unsorted");
      }
      const l = sorted[i];
      buf = ethers.concat([
        buf,
        ethers.solidityPacked(
          ["bytes32", "bytes32", "uint256", "uint256", "bool"],
          [l.id, l.hash, BigInt(l.amount), BigInt(l.expiry), !!l.payerIsA],
        ),
      ]);
    }
    return ethers.keccak256(buf);
  }

  /**
   * stateDigest — the nine words both parties sign.
   *
   * chainId and contract are in there so a state signed for one deployment
   * cannot be replayed against another; the root so a state cannot be separated
   * from its locks; the withdrawals so it cannot be separated from the value
   * leaving under it. All nine, always — an ordinary payment signs zeros for the
   * withdrawals, which is not a special case but a true statement that it moves
   * nothing out of the contract.
   */
  function stateDigest(s) {
    return ethers.keccak256(
      abi.encode(
        ["uint8", "uint256", "address", "bytes32", "uint64", "uint256", "uint256", "bytes32", "uint256", "uint256"],
        [
          // The operation domain, FIRST. Without it an ordinary agreed state
          // hashes identically to a cooperative close whenever there are no
          // live locks, so signing "the balance is 400/100" would also be
          // signing "settle this channel now". This client only ever signs
          // ordinary states, so it defaults to OP_STATE and never guesses.
          Number(s.op || OP_STATE),
          BigInt(s.chainId),
          ethers.getAddress(s.contract),
          s.id,
          BigInt(s.nonce),
          BigInt(s.balanceA),
          BigInt(s.balanceB),
          s.htlcRoot || ZERO32,
          BigInt(s.withdrawA || 0),
          BigInt(s.withdrawB || 0),
        ],
      ),
    );
  }

  /**
   * EIP-191, which the contract applies before ecrecover.
   *
   * The step most easily forgotten: signatures over the raw digest verify
   * perfectly everywhere off chain and are rejected on it. personal_sign does
   * this wrapping itself, so this exists to CHECK a signature, not to sign one —
   * wrapping twice would be its own quiet disaster.
   */
  function personalDigest(raw) {
    return ethers.keccak256(
      ethers.concat([ethers.toUtf8Bytes("\x19Ethereum Signed Message:\n32"), raw]),
    );
  }

  /**
   * Recovers the signer of a raw digest from an r‖s‖v signature.
   *
   * Tolerates the 0x prefix or its absence. Wallets return one and the protocol
   * wire carries the other, and a mismatch there produced the single least
   * informative failure available: "signature must be 65 bytes", about a
   * signature that was perfectly valid.
   */
  function recoverSigner(rawDigest, signature) {
    return ethers.recoverAddress(personalDigest(rawDigest), "0x" + strip(signature));
  }

  // ---- 2. P8-a. wallet connection --------------------------------------------

  /**
   * Connects and reports who and where.
   *
   * The account IS the channel party — channelId derives from it — so an account
   * switch is a different channel, not a different session. And the chain id is
   * inside every digest, so a wallet on the wrong network produces signatures
   * valid nowhere. Both are read here and both are re-read before signing.
   */
  async function connect(provider = globalThis.ethereum) {
    if (!provider) {
      throw new TipError("no wallet found in this browser", "no_wallet");
    }
    const accounts = await provider.request({ method: "eth_requestAccounts" });
    if (!accounts || accounts.length === 0) {
      throw new TipError("wallet returned no account", "no_account");
    }
    const chainId = await provider.request({ method: "eth_chainId" });
    return {
      provider,
      address: ethers.getAddress(accounts[0]),
      chainId: BigInt(chainId),
    };
  }

  /**
   * Calls back when the wallet's account or network changes, and returns an
   * unsubscribe.
   *
   * Worth wiring even for a single tip: a user who switches accounts mid-flow
   * is now a different party, and a page that carried on would be signing as
   * somebody who never agreed to anything.
   */
  function watchWallet(session, onChange) {
    const provider = session.provider;
    if (!provider || typeof provider.on !== "function") return () => {};

    const accountsChanged = (accounts) => {
      const next = accounts && accounts.length ? ethers.getAddress(accounts[0]) : null;
      if (next !== session.address) onChange({ reason: "account", address: next });
    };
    const chainChanged = (chainId) => onChange({ reason: "chain", chainId: BigInt(chainId) });

    provider.on("accountsChanged", accountsChanged);
    provider.on("chainChanged", chainChanged);
    return () => {
      if (typeof provider.removeListener !== "function") return;
      provider.removeListener("accountsChanged", accountsChanged);
      provider.removeListener("chainChanged", chainChanged);
    };
  }

  /** Throws if the wallet has moved out from under a flow already in progress. */
  async function assertSameWallet(session) {
    const accounts = await session.provider.request({ method: "eth_accounts" });
    const now = accounts && accounts.length ? ethers.getAddress(accounts[0]) : null;
    if (now !== session.address) {
      throw new TipError(
        `wallet switched from ${session.address} to ${now}`,
        "wallet_changed",
      );
    }
    const chainId = BigInt(await session.provider.request({ method: "eth_chainId" }));
    if (chainId !== BigInt(session.chainId)) {
      throw new TipError(
        `wallet switched from chain ${session.chainId} to ${chainId}`,
        "chain_changed",
      );
    }
  }

  // ---- 3. P8-b. channel opening and funding ----------------------------------

  const SELECTOR = {
    // approve(address,uint256)
    approve: "0x095ea7b3",
    // openChannel(address,uint256)
    openChannel: "0x24f453d1",
    // deposit(bytes32,uint256)
    deposit: "0x1de26e16",
    // channels(bytes32)
    channels: "0x7a7ebd7b",
    // token() on the manager — the ERC-20 it will actually pull from.
    token: "0xfc0c546a",
    // balanceOf(address)
    balanceOf: "0x70a08231",
    // allowance(address,address)
    allowance: "0xdd62ed3e",
    // decimals()
    decimals: "0x313ce567",
  };

  // The order the public channels(bytes32) getter returns the struct in.
  const CHANNEL_TUPLE = [
    "address", "address", "uint256", "uint256", "uint8",
    "uint256", "uint256", "uint64", "uint256", "bytes32", "uint256",
  ];

  // Status, from the contract's enum. `None` is what an untouched struct reads
  // as, so it is also what "these two have never opened a channel" looks like.
  const STATUS = { NONE: 0, OPEN: 1, CLOSING: 2, SETTLED: 3 };

  /**
   * The ERC-20 the MANAGER will pull from, asked of the manager.
   *
   * Never taken from the server. `approve` hands a contract permission to move
   * a token balance, so being told which token to approve is being told which
   * balance to expose — and the only address whose answer cannot be wrong here
   * is the contract that will do the pulling.
   */
  async function managerToken(session, { manager }) {
    const raw = await session.provider.request({
      method: "eth_call",
      params: [{ to: ethers.getAddress(manager), data: SELECTOR.token }, "latest"],
    });
    if (!raw || raw === "0x") {
      throw new TipError("that address does not answer token()", "not_a_manager");
    }
    return ethers.getAddress("0x" + raw.slice(-40));
  }

  /**
   * ERC-20 decimals, asked of the token.
   *
   * Read rather than assumed to be 18. A whole-coin figure converted with the
   * wrong exponent is off by orders of magnitude in one direction or the other,
   * and this codebase has already shipped that bug once — a browser tip of "5"
   * that moved 5 base units because the conversion was skipped.
   */
  async function tokenDecimals(session, { token }) {
    const raw = await session.provider.request({
      method: "eth_call",
      params: [{ to: ethers.getAddress(token), data: SELECTOR.decimals }, "latest"],
    });
    if (!raw || raw === "0x") {
      throw new TipError("the token did not answer decimals", "token_unreadable");
    }
    return Number(BigInt(raw));
  }

  /** ERC-20 balanceOf, as base units. */
  async function tokenBalance(session, { token, owner }) {
    const raw = await session.provider.request({
      method: "eth_call",
      params: [{
        to: ethers.getAddress(token),
        data: SELECTOR.balanceOf + encodeAddress(owner),
      }, "latest"],
    });
    if (!raw || raw === "0x") {
      throw new TipError("the token did not answer balanceOf", "token_unreadable");
    }
    return BigInt(raw);
  }

  /** ERC-20 allowance, as base units. */
  async function tokenAllowance(session, { token, owner, spender }) {
    const raw = await session.provider.request({
      method: "eth_call",
      params: [{
        to: ethers.getAddress(token),
        data: SELECTOR.allowance + encodeAddress(owner) + encodeAddress(spender),
      }, "latest"],
    });
    if (!raw || raw === "0x") {
      throw new TipError("the token did not answer allowance", "token_unreadable");
    }
    return BigInt(raw);
  }

  /**
   * What the chain says about this pair, WITHOUT throwing.
   *
   * `openingState` throws, because by the time a tip is being built an absent
   * channel is an error. Deciding whether to OFFER channel setup is the
   * opposite question, asked before anything has gone wrong, and a thrown error
   * is a poor way to answer "is there one?".
   */
  async function channelSnapshot(session, { manager, id, recipient }) {
    const onChain = await readChannel(session, { manager, id });
    const [partyA, partyB] = sortParties(session.address, recipient);
    const parties =
      ethers.getAddress(onChain.partyA) === partyA &&
      ethers.getAddress(onChain.partyB) === partyB;
    const mineIsA = isPartyA(session.address, recipient);
    return {
      id,
      status: onChain.status,
      exists: onChain.status !== STATUS.NONE,
      open: onChain.status === STATUS.OPEN,
      partiesMatch: parties,
      depositA: onChain.depositA,
      depositB: onChain.depositB,
      mine: mineIsA ? onChain.depositA : onChain.depositB,
      theirs: mineIsA ? onChain.depositB : onChain.depositA,
    };
  }

  /**
   * Block until a transaction is mined, or say plainly that we stopped waiting.
   *
   * A pending transaction and a failed one are different facts and the caller
   * must be able to tell them apart: `timeout` means it may still confirm, and
   * telling somebody their approval failed when it is merely slow invites them
   * to send it a second time.
   */
  async function awaitReceipt(session, txHash, options = {}) {
    const timeoutMs = options.timeoutMs ?? 300000;
    const pollMs = options.pollMs ?? 3000;
    const sleep = options.sleep || ((ms) => new Promise((r) => setTimeout(r, ms)));
    const now = options.now || (() => Date.now());
    const deadline = now() + timeoutMs;
    for (;;) {
      const receipt = await session.provider.request({
        method: "eth_getTransactionReceipt",
        params: [txHash],
      });
      if (receipt) {
        // status "0x0" is a REVERT that was mined. It is a definite failure,
        // unlike the timeout below, and must never be reported as one.
        if (BigInt(receipt.status ?? "0x1") === 0n) {
          throw new TipError("the transaction was mined but reverted", "reverted");
        }
        return receipt;
      }
      if (now() >= deadline) {
        throw new TipError(
          "the transaction has not been mined yet", "pending");
      }
      await sleep(pollMs);
    }
  }

  /**
   * Reads a channel from the CHAIN.
   *
   * This is invariant P5-1 as it applies to the browser: a channel's deposited
   * value is never established from peer-provided data. The node is asked what
   * the parties have SIGNED; it is never asked what was DEPOSITED, because a
   * node that could inflate the deposits could invite a tipper to sign a state
   * spending money that was never there.
   *
   * The call goes through the wallet's provider, which is the one RPC endpoint
   * the user has already chosen to trust.
   */
  async function readChannel(session, { manager, id }) {
    const raw = await session.provider.request({
      method: "eth_call",
      params: [{ to: ethers.getAddress(manager), data: SELECTOR.channels + strip(id) }, "latest"],
    });
    if (!raw || raw === "0x") {
      throw new TipError("the chain returned nothing for this channel", "no_channel");
    }
    const d = abi.decode(CHANNEL_TUPLE, raw);
    return {
      partyA: d[0],
      partyB: d[1],
      depositA: d[2],
      depositB: d[3],
      status: Number(d[4]),
      nonce: d[7],
    };
  }

  /**
   * Funds a channel: approve the token, then open.
   *
   * Two transactions, sent by the TIPPER. Presented honestly as funding a
   * prepaid balance rather than as "one click to tip" — the first tip costs a
   * transaction and every later one does not, and a user told otherwise will
   * feel misled at exactly the wrong moment.
   *
   * Crash-safe by construction: the id is derived BEFORE anything is sent, so a
   * page reloaded mid-sequence asks the chain what happened rather than asking
   * the user whether they think it worked. See resumeOpen.
   */
  /**
   * ERC-20 approve. One transaction, and the wallet prompts for it.
   *
   * Split out of openChannel so a caller that has ALREADY got a sufficient
   * allowance can skip it. Asking somebody to sign an approval they do not need
   * costs them gas and teaches them to click through wallet prompts, which is
   * the habit every drainer relies on.
   */
  async function approveToken(session, { token, spender, amount }) {
    await assertSameWallet(session);
    return session.provider.request({
      method: "eth_sendTransaction",
      params: [
        {
          from: session.address,
          to: ethers.getAddress(token),
          data: SELECTOR.approve + encodeAddress(spender) + encodeUint(amount),
        },
      ],
    });
  }

  /** openChannel(partner, deposit). The second of the two transactions. */
  async function openChannelTx(session, { recipient, deposit, manager }) {
    await assertSameWallet(session);
    return session.provider.request({
      method: "eth_sendTransaction",
      params: [
        {
          from: session.address,
          to: ethers.getAddress(manager),
          data: SELECTOR.openChannel + encodeAddress(recipient) + encodeUint(deposit),
        },
      ],
    });
  }

  /**
   * Two transactions, sent by the TIPPER, back to back.
   *
   * Kept as it was — approve then open, unconditionally — because callers exist
   * that want exactly that. The staged flow in tip-flow.js uses the two halves
   * above instead, so it can check the allowance in between and skip the first.
   */
  async function openChannel(session, { recipient, deposit, token, manager }) {
    await assertSameWallet(session);
    const id = deriveChannelId(session.address, recipient);
    const approveTx = await approveToken(session, { token, spender: manager, amount: deposit });
    const openTx = await openChannelTx(session, { recipient, deposit, manager });
    return { id, approveTx, openTx, partyA: isPartyA(session.address, recipient) };
  }

  /** Adds value to a channel that already exists. */
  async function deposit(session, { id, amount, token, manager }) {
    await assertSameWallet(session);
    const approveTx = await session.provider.request({
      method: "eth_sendTransaction",
      params: [
        {
          from: session.address,
          to: ethers.getAddress(token),
          data: SELECTOR.approve + encodeAddress(manager) + encodeUint(amount),
        },
      ],
    });
    const depositTx = await session.provider.request({
      method: "eth_sendTransaction",
      params: [
        {
          from: session.address,
          to: ethers.getAddress(manager),
          data: SELECTOR.deposit + strip(id) + encodeUint(amount),
        },
      ],
    });
    return { id, approveTx, depositTx };
  }

  // ---- 4. P8-c. signing ------------------------------------------------------

  // secp256k1n/2. The contract rejects s above this, so a signature accepted
  // here but not there would be a state that settles nowhere — caught in the
  // browser, where it can still be retried, rather than at settlement.
  const HALF_ORDER = BigInt(
    "0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0",
  );

  /**
   * Signs a raw digest with the wallet and verifies the result before returning.
   *
   * The verification is not ceremony. A signature that recovers to the wrong
   * address, or carries a high s, is worthless to the contract; discovering that
   * here costs a retry, and discovering it at settlement costs the channel.
   */
  async function signDigest(session, rawDigest) {
    const signature = await session.provider.request({
      method: "personal_sign",
      params: [rawDigest, session.address],
    });
    assertLowS(signature);
    const signer = recoverSigner(rawDigest, signature);
    if (signer !== session.address) {
      throw new TipError(
        `signature recovers to ${signer}, not ${session.address}`,
        "bad_signature",
      );
    }
    return signature;
  }

  function assertLowS(signature) {
    const sig = ethers.Signature.from("0x" + strip(signature));
    if (BigInt(sig.s) > HALF_ORDER) {
      throw new TipError("wallet produced a high-s signature", "high_s");
    }
  }

  // ---- 5. the peer conversation ----------------------------------------------

  /**
   * One SCPP/1 frame to the node, one frame back.
   *
   * Deliberately no retry. A retry here is a policy decision about money — it
   * belongs to the caller that knows the intent is idempotent, not to the thing
   * that moves bytes. Same rule the Go transport follows.
   *
   * Returns null when the node had nothing to say (204), which is a real answer.
   */
  async function exchange(endpoint, envelope) {
    let response;
    try {
      response = await fetchImpl(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(envelope),
        // No cookies. This endpoint authorises by signature, and sending
        // ambient credentials to it would be meaningless at best.
        credentials: "omit",
      });
    } catch (err) {
      // TAGGED so a caller can classify it, and NOT otherwise interpreted here.
      // A transport failure says only that the exchange did not finish; whether
      // the node acted on the frame depends on WHICH frame it was, and that is
      // knowable one level up and nowhere else.
      throw new TipError("the node could not be reached", "node_unreachable");
    }
    if (response.status === 204) return null;
    let body = null;
    try {
      body = await response.json();
    } catch {
      throw new TipError(`node returned unreadable body (${response.status})`, "bad_reply");
    }
    if (!response.ok && body && body.type !== MSG.ERROR) {
      throw new TipError(`node returned ${response.status}`, "node_error");
    }
    return body;
  }

  function envelope(type, channel, body) {
    const env = { v: PROTOCOL_VERSION, type };
    if (channel) env.channel = strip(channel);
    if (body !== undefined) env.body = body;
    return env;
  }

  /** Asks the node for the channel's current fully signed state. */
  async function fetchState(endpoint, id) {
    const reply = await exchange(endpoint, envelope(MSG.STATE_REQUEST, id, {}));
    if (!reply || reply.type !== MSG.STATE_RESPONSE) {
      throw new TipError("node did not answer with a state", "no_state");
    }
    return reply.body || { have: false };
  }

  // ---- 6. P8-d/e. tip initiation and off-chain state signing -----------------

  /**
   * A payment's identity, generated HERE and reused on retry.
   *
   * That reuse is what makes a retry safe, and the browser is where retries
   * actually happen — a user pressing the button again after a spinner stalls.
   * A fresh id on each press would turn one impatient user into two payments.
   */
  function newIntent() {
    return ethers.hexlify(randomBytes(32));
  }

  /**
   * Applies a transition to a state, locally.
   *
   * This is the whole reason the browser holds a model at all: the next state
   * has to be something this code DERIVED, so that the digest it signs is one it
   * can vouch for. A next state supplied by the node would make every check
   * below circular.
   */
  function applyTransition(current, { kind, amount, payerIsA, lock }) {
    const next = {
      nonce: BigInt(current.nonce) + 1n,
      balanceA: BigInt(current.balanceA),
      balanceB: BigInt(current.balanceB),
      locks: [...(current.locks || [])],
      // A payment moves nothing out of the contract. Carried explicitly rather
      // than defaulted, because they are signed either way.
      withdrawA: 0n,
      withdrawB: 0n,
    };
    const value = BigInt(amount);
    if (value <= 0n) throw new TipError("a tip must be positive", "bad_amount");

    const available = payerIsA ? next.balanceA : next.balanceB;
    if (value > available) {
      throw new TipError(
        `channel balance ${available} cannot cover ${value}`,
        "insufficient_balance",
      );
    }

    if (kind === KIND.PAY) {
      if (payerIsA) {
        next.balanceA -= value;
        next.balanceB += value;
      } else {
        next.balanceB -= value;
        next.balanceA += value;
      }
    } else if (kind === KIND.LOCK_ADD) {
      // Locked value leaves the payer's balance and enters NEITHER — while a
      // payment is in flight the payer can no longer spend it and the payee
      // cannot yet. Adding it to the payee's balance would show them money they
      // may never receive.
      if (payerIsA) next.balanceA -= value;
      else next.balanceB -= value;
      next.locks.push({
        id: lock.id,
        hash: lock.hash,
        amount: value.toString(),
        expiry: lock.expiry,
        payerIsA,
      });
    } else {
      throw new TipError(`this client cannot propose ${kind}`, "bad_kind");
    }
    return next;
  }

  /**
   * Sends a tip: fetch, derive, hash, CHECK, sign, propose.
   *
   * The check in the middle is the load-bearing step. The node supplies the
   * current state and its digest; this code rebuilds that digest from the parts
   * and refuses if they disagree. Without it, a node could hand over a state
   * whose stated numbers and actual digest differ, and the wallet would sign the
   * digest while the user read the numbers.
   */
  async function tip(session, params) {
    const {
      endpoint,
      recipient,
      amount,
      manager,
      kind = KIND.PAY,
      lock,
      intent = newIntent(),
    } = params;

    await assertSameWallet(session);

    const id = deriveChannelId(session.address, recipient);
    const payerIsA = isPartyA(session.address, recipient);
    const context = { chainId: session.chainId, contract: manager, id };

    // THE ONE PLACE A FALLBACK MAY BE DECIDED.
    //
    // fetchState is a STATE_REQUEST: a read that proposes nothing and changes
    // nothing. If the node cannot be reached HERE, then no proposal has been
    // made, no signature exists, and the recipient provably cannot have acted —
    // so the tip is safe to hand to a mailbox instead.
    //
    // Every later exchange carries a signed proposal, and a transport failure
    // there is ambiguous forever: the node may have received it, countersigned,
    // and had the reply lost. Those stay unreachable-and-unknown, and this
    // client deliberately does not offer callers a way to tell them apart from
    // here — the distinction is made once, at this line.
    let response;
    try {
      response = await fetchState(endpoint, id);
    } catch (err) {
      if (err instanceof TipError && err.code === "node_unreachable") {
        throw new TipError("the creator's node is not reachable", "recipient_unreachable");
      }
      throw err;
    }
    let current;

    if (response.have) {
      current = decodeState(response.state);
      if (strip(current.channel) !== strip(id)) {
        throw new TipError("node answered about a different channel", "wrong_channel");
      }

      // Re-derive the digest of what we were HANDED before trusting any of it.
      // A state whose parts do not reproduce its own digest is not a state, and
      // its signatures cover something else.
      const currentDigest = stateDigest({
        ...context, ...current, htlcRoot: htlcRoot(current.locks),
      });
      if (response.sig_a) {
        requireSigner(currentDigest, response.sig_a, sortParties(session.address, recipient)[0], "A");
      }
      if (response.sig_b) {
        requireSigner(currentDigest, response.sig_b, sortParties(session.address, recipient)[1], "B");
      }
    } else {
      // The first tip on a freshly opened channel. There is no prior signed
      // state, and the opening one is not a thing to be asked for — it is
      // whatever the chain says was deposited, at nonce 0. Taking it from the
      // node instead would let a node name its own opening balances.
      current = await openingState(session, { manager, id, recipient });
    }

    const next = applyTransition(current, { kind, amount, payerIsA, lock });
    const nextDigest = stateDigest({ ...context, ...next, htlcRoot: htlcRoot(next.locks) });

    // Conservation, checked before signing rather than hoped for after. The
    // total in the channel cannot change: a payment moves value between the two
    // sides and a lock parks it beside them.
    const before = BigInt(current.balanceA) + BigInt(current.balanceB) + lockedTotal(current.locks);
    const after = next.balanceA + next.balanceB + lockedTotal(next.locks);
    if (before !== after) {
      throw new TipError("this transition would create or destroy value", "not_conserved");
    }

    const signature = await signDigest(session, nextDigest);

    // From here a reply may or may not arrive, and the difference between "no
    // reply" and "rejected" is the difference between UNKNOWN and a definite no.
    let reply;
    try {
      reply = await exchange(
        endpoint,
        envelope(MSG.STATE_PROPOSE, id, {
          intent: strip(intent),
          transition: transitionWire({ kind, amount, lock }),
          state: encodeState(id, next),
          // Bare hex on the wire, as every other 32-byte-and-up value here is.
          sig: strip(signature),
        }),
      );
    } catch (err) {
      // The proposal was signed and may have been applied. Reporting a failure
      // here would invite the user to pay twice; the intent id is what makes
      // retrying safe, so it is handed back with the uncertainty.
      return { outcome: OUTCOME.UNKNOWN, intent, id, nonce: Number(next.nonce), detail: err.message };
    }

    if (!reply || reply.type === MSG.ERROR) {
      return {
        outcome: OUTCOME.UNKNOWN,
        intent,
        id,
        nonce: Number(next.nonce),
        detail: reply && reply.body ? reply.body.detail : "no reply",
      };
    }
    if (reply.type === MSG.STATE_REJECT) {
      // A deliberate refusal. Definite, and safe to report as such.
      return {
        outcome: OUTCOME.REJECTED,
        intent,
        id,
        reason: reply.body && reply.body.code,
        detail: reply.body && reply.body.detail,
      };
    }
    if (reply.type !== MSG.STATE_ACCEPT) {
      return { outcome: OUTCOME.UNKNOWN, intent, id, detail: `unexpected ${reply.type}` };
    }

    // The acceptance carries the recipient's signature over the same digest.
    // Verified rather than assumed: an "accept" this code cannot check is an
    // acknowledgement, not an agreement, and only the second is worth anything
    // if the channel ever has to be settled on chain.
    const counterparty = payerIsA
      ? sortParties(session.address, recipient)[1]
      : sortParties(session.address, recipient)[0];
    requireSigner(nextDigest, reply.body.sig, counterparty, "counterparty");

    return {
      outcome: OUTCOME.COMPLETED,
      intent,
      id,
      nonce: Number(next.nonce),
      digest: nextDigest,
      sig: signature,
      counterpartySig: reply.body.sig,
      // The co-signed state, in the shape anyone verifying it needs: the state
      // plus BOTH signatures, each in its own party's slot. Assembled here
      // because this is the one place that already knows which side the payer
      // is on — a caller working it out again is a caller that can get it
      // backwards, and a proof with the signatures swapped verifies as nothing.
      proof: {
        state: encodeState(id, next),
        sig_a: strip(payerIsA ? signature : reply.body.sig),
        sig_b: strip(payerIsA ? reply.body.sig : signature),
      },
    };
  }

  /**
   * The state a channel starts in: nonce 0, balances equal to the deposits.
   *
   * Read from the chain, and checked against the parties this client derived —
   * if the contract disagrees about who is in this channel, the id was computed
   * from the wrong addresses and nothing after that point would be meaningful.
   */
  async function openingState(session, { manager, id, recipient }) {
    const onChain = await readChannel(session, { manager, id });
    const [partyA, partyB] = sortParties(session.address, recipient);

    // STATUS FIRST, and this order is the whole point.
    //
    // A channel that was never opened reads back as an untouched struct: status
    // None AND both parties zero. With the parties compared first, that case
    // produced `wrong_parties` — "the channel on record is between different
    // wallets" — about a channel that is not on record at all. tip-flow.js maps
    // `wrong_parties` to UNKNOWN, so the honest, actionable answer ("you have no
    // channel yet, here is how to open one") was unreachable in the one
    // situation every new tipper is in.
    //
    // `no_channel` rather than `not_open`: on chain the two are the same fact,
    // since openChannel sets status and parties together, and one name for one
    // fact is what lets the caller offer setup instead of guessing.
    if (onChain.status === 0) {
      throw new TipError("these two wallets have no channel on chain", "no_channel");
    }
    if (
      ethers.getAddress(onChain.partyA) !== partyA ||
      ethers.getAddress(onChain.partyB) !== partyB
    ) {
      throw new TipError("the chain names different parties for this channel", "wrong_parties");
    }
    return {
      channel: id,
      nonce: 0n,
      balanceA: onChain.depositA,
      balanceB: onChain.depositB,
      withdrawA: 0n,
      withdrawB: 0n,
      locks: [],
    };
  }

  function requireSigner(digest, signature, expected, label) {
    let signer;
    try {
      signer = recoverSigner(digest, signature);
    } catch (err) {
      throw new TipError(`${label} signature is unreadable: ${err.message}`, "bad_signature");
    }
    if (signer !== ethers.getAddress(expected)) {
      throw new TipError(
        `${label} signature recovers to ${signer}, expected ${expected}`,
        "bad_signature",
      );
    }
  }

  // ---- 7. P8-f. crash and recovery -------------------------------------------

  /**
   * Settles an UNKNOWN outcome by asking the chain-and-state, not the user.
   *
   * A browser is the least reliable participant in this system: tabs close,
   * phones sleep, users navigate away mid-signature. The rule it inherits from
   * the node is that no layer may conclude a payment failed merely because
   * something stopped waiting for it.
   *
   * So recovery re-reads the authoritative state. If the node holds a state at
   * the nonce this payment would have produced, and it carries our signature,
   * the payment happened.
   */
  async function recoverPayment(session, { endpoint, recipient, nonce, manager }) {
    const id = deriveChannelId(session.address, recipient);
    const response = await fetchState(endpoint, id);
    if (!response.have) return { outcome: OUTCOME.UNKNOWN, id, detail: "node holds no state" };

    const current = decodeState(response.state);
    if (BigInt(current.nonce) >= BigInt(nonce)) {
      const digest = stateDigest({
        chainId: session.chainId,
        contract: manager,
        id,
        ...current,
        htlcRoot: htlcRoot(current.locks),
      });
      const mine = isPartyA(session.address, recipient) ? response.sig_a : response.sig_b;
      if (mine && recoverSigner(digest, mine) === session.address) {
        return { outcome: OUTCOME.COMPLETED, id, nonce: Number(current.nonce) };
      }
    }
    // The node is behind the nonce we signed at. That is not proof of failure —
    // it may not have processed the proposal yet — so the honest answer is that
    // it is still unknown, and the caller may retry the same intent.
    return { outcome: OUTCOME.UNKNOWN, id, nonce: Number(current.nonce) };
  }

  /**
   * Recovers an interrupted open. The id was derivable before the transaction
   * was sent, so the chain can simply be asked.
   */
  function resumeOpen(session, recipient) {
    return {
      id: deriveChannelId(session.address, recipient),
      partyA: isPartyA(session.address, recipient),
    };
  }

  // ---- 8. wire encoding ------------------------------------------------------
  //
  // Amounts are DECIMAL STRINGS on the wire, never JS numbers: 100 AXON is 1e20
  // wei, and Number.MAX_SAFE_INTEGER is about 9e15. A number here would silently
  // round somebody's money.

  function encodeState(id, s) {
    const out = {
      channel: strip(id),
      nonce: Number(s.nonce),
      balance_a: s.balanceA.toString(),
      balance_b: s.balanceB.toString(),
    };
    if (s.locks && s.locks.length) {
      out.pending = [...s.locks]
        .sort((p, q) => (BigInt(p.id) < BigInt(q.id) ? -1 : 1))
        .map((l) => ({
          id: strip(l.id),
          hash: strip(l.hash),
          amount: BigInt(l.amount).toString(),
          expiry: Number(l.expiry),
          payer_is_a: !!l.payerIsA,
        }));
    }
    // Only when non-zero, matching the node's encoder exactly — these are inside
    // the digest, so the two sides must agree on when they appear.
    if (BigInt(s.withdrawA || 0) > 0n) out.withdraw_a = BigInt(s.withdrawA).toString();
    if (BigInt(s.withdrawB || 0) > 0n) out.withdraw_b = BigInt(s.withdrawB).toString();
    return out;
  }

  function decodeState(w) {
    return {
      channel: "0x" + strip(w.channel || ""),
      nonce: BigInt(w.nonce || 0),
      balanceA: BigInt(w.balance_a || 0),
      balanceB: BigInt(w.balance_b || 0),
      withdrawA: BigInt(w.withdraw_a || 0),
      withdrawB: BigInt(w.withdraw_b || 0),
      locks: (w.pending || []).map((l) => ({
        id: "0x" + strip(l.id),
        hash: "0x" + strip(l.hash),
        amount: BigInt(l.amount || 0),
        expiry: Number(l.expiry || 0),
        payerIsA: !!l.payer_is_a,
      })),
    };
  }

  function transitionWire({ kind, amount, lock }) {
    const out = { kind, amount: BigInt(amount).toString() };
    if (lock) {
      out.lock_id = strip(lock.id);
      out.hash = strip(lock.hash);
      out.expiry = Number(lock.expiry);
    }
    return out;
  }

  function lockedTotal(locks) {
    return (locks || []).reduce((sum, l) => sum + BigInt(l.amount), 0n);
  }

  function encodeAddress(a) {
    return strip(ethers.zeroPadValue(ethers.getAddress(a), 32));
  }

  function encodeUint(n) {
    return strip(ethers.zeroPadValue(ethers.toBeHex(BigInt(n)), 32));
  }


  /**
   * Ask a volunteer for the frames it retains for one of MY channels.
   *
   * Returns them unverified and unsorted. Verification is recoverLatest's job
   * and happens before any of this is used, because a volunteer is a cache and
   * a cache is not an authority.
   */
  /**
   * NOT YET WIRED INTO THE PRODUCT — see proposeEnvelope's `base` parameter.
   *
   * This and selectLatest are how a contributor sends a SECOND mailbox tip:
   * recover the state they signed last time, verify it, and continue from it.
   * tip-flow.js currently calls proposeEnvelope with no `base`, so a second tip
   * would rebuild from the chain and reuse the first tip's update number.
   *
   * Kept, not deleted, precisely because that gap needs this machinery. The
   * recipient-side collection module that used to be the other consumer is
   * gone: collection moved into the node's own console, where the key is.
   */
  async function statesFromMailbox(volunteer, { recipient, caller, channel, token, sig }) {
    if (!/^https:\/\//.test(String(volunteer))) {
      throw new TipError("a volunteer endpoint must be https", "insecure_endpoint");
    }
    let response;
    try {
      response = await fetchImpl(mailboxURL(volunteer, "states"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "omit",
        body: JSON.stringify({ recipient, caller, channel, token, sig }),
      });
    } catch (err) {
      throw new TipError("the volunteer could not be reached", "volunteer_unreachable");
    }
    if (!response.ok) {
      throw new TipError("the volunteer would not hand over the chain", "states_refused");
    }
    const body = await response.json();
    return Array.isArray(body.frames) ? body.frames : [];
  }

  /**
   * Pick the state to build the next tip on, from candidates a volunteer held.
   *
   * WHAT "HIGHEST" MEANS HERE, precisely. Not "the biggest nonce in the list" —
   * every candidate is verified FIRST and only survivors are ranked. A volunteer
   * that appended a forged state with a huge nonce contributes nothing, because
   * a forged state has no valid signature over a digest this code recomputed.
   *
   * NOTHING IS TAKEN FROM THE ENVELOPE'S METADATA. The channel, nonce and
   * balances all come from the signed state itself, re-encoded here and hashed
   * here; the frame's `channel` field is routing and is checked against the id
   * this wallet derived, never used in its place.
   *
   * I4: two DIFFERENT valid states at one nonce means somebody signed twice, and
   * this code cannot know which is real. It refuses the channel rather than
   * picking, because picking is how a double-spend gets laundered into a base
   * state for the next tip.
   */
  function selectLatest(frames, { chainId, contract, id, me, recipient }, options = {}) {
    // coSignedOnly: BOTH parties must have signed before a state may be used.
    //
    // Off by default, because choosing which proposal to accept means ranking
    // proposals, and those carry one signature by definition.
    //
    // On for BASE RECOVERY, and this is the distinction that matters. A bare
    // proposal is the contributor's own unilateral claim: the recipient has
    // agreed to nothing. Building tip 2 on it would advance this wallet's
    // chain on its own say-so, and if the recipient never accepted tip 1 the
    // contributor would be signing a state nobody else has ever endorsed.
    const coSignedOnly = options.coSignedOnly === true;
    const [partyA, partyB] = sortParties(me, recipient);
    const byNonce = new Map();

    for (const frame of frames || []) {
      let candidate;
      try {
        const body = frame && frame.body ? frame.body : {};
        candidate = decodeState(body.state);
        // The channel is derived from MY wallet and the recipient. A state
        // about any other channel is not evidence about this one.
        if (strip(candidate.channel) !== strip(id)) continue;

        const digest = stateDigest({
          chainId, contract, id, ...candidate, htlcRoot: htlcRoot(candidate.locks),
        });
        // At least one real signature over exactly these bytes. A proposal
        // carries the proposer's; a co-signed state carries both.
        let signed = false;
        if (body.sig_a) { requireSigner(digest, body.sig_a, partyA, "A"); signed = true; }
        if (body.sig_b) { requireSigner(digest, body.sig_b, partyB, "B"); signed = true; }
        if (coSignedOnly) {
          // Both, or it is not evidence of an agreement. Checked on the
          // signatures actually verified above, not on the fields being
          // present: a frame carrying sig_a and sig_b that do not recover
          // correctly has already thrown out of this block.
          if (!(body.sig_a && body.sig_b)) continue;
        } else if (body.sig && !signed) {
          // A bare proposal signature: it must belong to one of the parties.
          // recoverSigner applies EIP-191 itself; wrapping it again here
          // hashes the wrapper and recovers a stranger.
          const who = recoverSigner(digest, body.sig);
          if (who !== partyA && who !== partyB) continue;
          signed = true;
        }
        if (!signed) continue;
      } catch (err) {
        // An unverifiable frame is not evidence. Skipped rather than fatal: a
        // volunteer may legitimately be holding something for a different
        // deployment, and one bad frame must not deny a contributor their chain.
        continue;
      }

      const nonce = BigInt(candidate.nonce);
      const key = String(nonce);
      const seen = byNonce.get(key);
      if (seen && stateDigest({ chainId, contract, id, ...seen, htlcRoot: htlcRoot(seen.locks) })
          !== stateDigest({ chainId, contract, id, ...candidate, htlcRoot: htlcRoot(candidate.locks) })) {
        throw new TipError(
          `two different states are signed at nonce ${key}; this channel is not safe to build on`,
          "conflicting_states");
      }
      byNonce.set(key, candidate);
    }

    let best = null;
    for (const st of byNonce.values()) {
      if (!best || BigInt(st.nonce) > BigInt(best.nonce)) best = st;
    }
    return best;
  }

  /**
   * The exact bytes a mailbox checks a reader against.
   *
   * Reproduced from MailboxChallenge in the node, field for field including the
   * newlines and the lower-cased address. A challenge that differs by one byte
   * produces a signature that recovers to a stranger, and the volunteer refuses
   * with a message about the wrong party — which reads like a permission
   * problem and is really an encoding one.
   */
  function mailboxChallenge(nodeId, address, token) {
    return ethers.keccak256(ethers.toUtf8Bytes(
      "syndichan-mailbox-collect:v1\n" + String(nodeId) + "\n"
      + String(address).toLowerCase() + "\n" + String(token)));
  }

  /**
   * Recover the state this contributor should build their NEXT tip on.
   *
   * WHY THIS EXISTS
   * ---------------
   * In mailbox mode the recipient's node is by definition not answering, so
   * proposeEnvelope falls back to the chain. That is right for a first tip and
   * wrong for a second: the chain has not moved, so tip 2 would reuse tip 1's
   * update number and the two would collide at the recipient.
   *
   * WHAT IT WILL AND WILL NOT BUILD ON
   * ----------------------------------
   * Only a CO-SIGNED state — one the recipient's node has actually accepted.
   * A contributor's own queued-but-unaccepted proposal is not an agreement and
   * cannot advance their chain.
   *
   * Everything else is already refused downstream and is left there rather than
   * duplicated here: selectLatest recomputes every digest and drops forgeries,
   * refuses two different states at one nonce, and derives the channel from
   * this wallet and the recipient rather than believing the frame; and
   * proposeEnvelope refuses a base older than the chain.
   *
   * NULL MEANS "THE VOLUNTEER ANSWERED AND HELD NOTHING" — an ordinary first
   * tip, where the chain is the correct base.
   *
   * A FAILURE TO LOOK THROWS, and is deliberately not flattened into null. The
   * two are not the same: if this wallet has already had a tip accepted and we
   * cannot find out, building on the chain proposes a state at an update number
   * the recipient already holds. They would refuse it — nothing is paid twice —
   * but the contributor would have been told their tip was queued when it can
   * never be accepted. The caller reports that honestly instead.
   */
  async function recoverBase(session, { volunteer, nodeId, recipient, manager }) {
    if (!volunteer || !nodeId) return null;
    const id = deriveChannelId(session.address, recipient);
    // A per-attempt token, so a captured proof cannot answer a later read.
    const token = "tip-" + strip(newIntent()).slice(0, 24);
    const challenge = mailboxChallenge(nodeId, session.address, token);

    // The wallet proves this caller IS the contributor. The mailbox derives the
    // channel from caller+recipient itself, so naming somebody else's channel
    // here gets nothing. Errors travel — see above.
    // PRE-WRAPPED, ONCE. The mailbox verifies with RecoverSigner(PersonalDigest(
    // challenge), proof), and RecoverSigner applies EIP-191 itself — so the
    // bytes actually signed are the challenge wrapped TWICE. Signing the bare
    // challenge here recovers to a stranger and the volunteer refuses with
    // "does not serve that recipient", which names the wrong problem entirely:
    // it reads as a lapsed authorization and is an encoding mismatch.
    const sig = await signDigest(session, personalDigest(challenge));
    const frames = await statesFromMailbox(volunteer, {
      recipient, caller: session.address, channel: strip(id), token, sig,
    });
    return selectLatest(frames, {
      chainId: session.chainId, contract: manager, id,
      me: session.address, recipient,
    }, { coSignedOnly: true });
  }

  /**
   * Build a signed STATE_PROPOSE without sending it, for a mailbox.
   *
   * Same construction as tip(): derive the channel, apply the transition,
   * check conservation, sign the digest. The ONLY difference is where the
   * base state comes from — tip() asks the recipient's node, and in mailbox
   * mode that node is by definition not answering.
   *
   * SO THE BASE IS THE CHAIN. openingState reads ChannelManagerV2 and refuses
   * unless the chain names these two parties and the channel is open, which is
   * an authority the recipient's absence cannot weaken.
   *
   * REPEATED TIPS. The chain is the base only when nothing newer exists. When
   * `base` is supplied — a state recovered from the volunteer and verified by
   * selectLatest — it is used instead, so tip 2 continues from tip 1 rather
   * than reusing its nonce. The caller does the recovery because the caller is
   * the one that knows which volunteer to ask.
   */
  async function proposeEnvelope(session, params) {
    const { endpoint, recipient, amount, manager, base,
            kind = KIND.PAY, intent = newIntent() } = params;
    await assertSameWallet(session);

    const id = deriveChannelId(session.address, recipient);
    const payerIsA = isPartyA(session.address, recipient);
    const context = { chainId: session.chainId, contract: manager, id };

    // The chain is the FLOOR, not the answer: a verified newer state wins, and
    // a `base` older than the chain is refused rather than used, because that
    // would propose a nonce the contract has already moved past.
    const onChain = await openingState(session, { manager, id, recipient });
    let current = onChain;
    if (base) {
      if (strip(base.channel) !== strip(id)) {
        throw new TipError("that base state is for another channel", "wrong_channel");
      }
      if (BigInt(base.nonce) < BigInt(onChain.nonce)) {
        throw new TipError("that base state is older than the chain", "stale_base");
      }
      current = base;
    }
    const next = applyTransition(current, { kind, amount, payerIsA });

    const before = BigInt(current.balanceA) + BigInt(current.balanceB);
    const after = BigInt(next.balanceA) + BigInt(next.balanceB);
    if (before !== after) {
      throw new TipError("this transition would create or destroy value", "not_conserved");
    }
    const signature = await signDigest(session, stateDigest({
      ...context, ...next, htlcRoot: htlcRoot(next.locks),
    }));

    return envelope(MSG.STATE_PROPOSE, id, {
      intent: strip(intent),
      transition: transitionWire({ kind, amount }),
      state: encodeState(id, next),
      sig: strip(signature),
    });
  }

  // ---- 6. the volunteer mailbox ----------------------------------------------
  //
  // WHY THIS IS NOT `exchange`
  // --------------------------
  // exchange() is a conversation: one frame out, one frame back, and the reply
  // is what tells the payer the recipient agreed. A mailbox has no reply,
  // because the recipient is not there — that is the entire reason a mailbox
  // exists. It answers 202 to say "I am holding this", which is a statement
  // about storage and NOT about payment.
  //
  // So a mailbox delivery is deliberately a different function with a different
  // return value. Folding it into exchange() would let a queued frame flow into
  // the same code path that reports a completed tip, and "your tip was sent"
  // would come to mean "somebody wrote it down".

  /** Where the mailbox routes live, relative to the volunteer's base URL. */
  function mailboxURL(endpoint, action) {
    return String(endpoint).replace(/\/scpp\/v1\/?$/, "").replace(/\/+$/, "") +
      "/mailbox/v1/" + action;
  }

  /**
   * Hand a frame to a volunteer to hold for a recipient who is not online.
   *
   * Returns {queued: true} and NOTHING ELSE that a caller could mistake for a
   * completed payment. There is no signature to check here, because the
   * volunteer produced none and is not supposed to be able to.
   *
   * The frame is the same SCPP/1 envelope the recipient's own node would have
   * received. It is not re-encoded, re-signed or altered for the mailbox — a
   * second encoding of a signed thing is a second chance to encode it wrongly.
   */
  async function deliverToMailbox(endpoint, recipient, envelope) {
    if (!/^https:\/\//.test(String(endpoint))) {
      // Same rule the direct path applies. A mailbox reached over http could be
      // rewritten in flight by anyone on the network.
      throw new TipError("a volunteer endpoint must be https", "insecure_endpoint");
    }
    let response;
    try {
      response = await fetchImpl(mailboxURL(endpoint, "deliver"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "omit",
        body: JSON.stringify({ recipient, envelope }),
      });
    } catch (err) {
      throw new TipError("the volunteer could not be reached", "volunteer_unreachable");
    }
    if (response.status === 403) {
      // The volunteer does not serve this recipient. NOT a payment failure and
      // not the recipient's fault: the creator's setup names a volunteer that
      // has not agreed to carry for them.
      throw new TipError("that volunteer does not carry tips for this creator",
        "volunteer_not_serving");
    }
    if (response.status !== 202) {
      throw new TipError("the volunteer refused the message", "volunteer_refused");
    }
    return { queued: true };
  }

  /**
   * Collect frames a volunteer is holding for you.
   *
   * The caller proves who it is by signing a challenge the volunteer can
   * recompute. Note what is NOT proved: nothing about the frames. They are
   * whatever somebody handed the volunteer, and every one of them is checked by
   * the recipient's own node before it is acted on — a mailbox is not trusted
   * to have carried honestly, only to have carried.
   */
  async function collectFromMailbox(endpoint, recipient, token, sig) {
    const response = await fetchImpl(mailboxURL(endpoint, "collect"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "omit",
      body: JSON.stringify({ recipient, token, sig }),
    });
    if (!response.ok) {
      throw new TipError("the volunteer refused to hand over the mail", "collect_refused");
    }
    const body = await response.json();
    return Array.isArray(body.frames) ? body.frames : [];
  }

  return {
    // digest
    deriveChannelId,
    sortParties,
    isPartyA,
    htlcRoot,
    stateDigest,
    personalDigest,
    recoverSigner,
    // wallet
    connect,
    watchWallet,
    assertSameWallet,
    // opening
    openChannel,
    approveToken,
    openChannelTx,
    deposit,
    resumeOpen,
    readChannel,
    openingState,
    channelSnapshot,
    managerToken,
    tokenDecimals,
    tokenBalance,
    tokenAllowance,
    awaitReceipt,
    STATUS,
    // signing
    signDigest,
    assertLowS,
    // paying
    newIntent,
    applyTransition,
    tip,
    // volunteer mailbox — queued, never "sent"
    proposeEnvelope,
    statesFromMailbox,
    selectLatest,
    mailboxChallenge,
    recoverBase,
    mailboxURL,
    deliverToMailbox,
    collectFromMailbox,
    fetchState,
    exchange,
    // recovery
    recoverPayment,
    // wire
    encodeState,
    decodeState,
  };
}

const ZERO32 = "0x" + "00".repeat(32);

function strip(hex) {
  return String(hex).replace(/^0x/, "");
}

function defaultRandomBytes(n) {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

// Convenience for a page that already loaded chain-bundle.js. Guarded so that
// importing this module under node — where there is no window and no bundle —
// does not throw.
if (typeof globalThis.window !== "undefined" && globalThis.window.PoFChain) {
  globalThis.window.TipChannel = createTipChannel(globalThis.window.PoFChain.ethers);
}
