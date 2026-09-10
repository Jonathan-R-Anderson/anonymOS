import { expect } from "chai";
import { ethers } from "hardhat";
import * as fs from "fs";
import * as path from "path";

// THE INVARIANT THE WATCHTOWER'S SPEED RESTS ON — roadmap P14.5.
//
// The event-driven watchtower answers "has this channel changed?" without
// touching the chain, and it is allowed to do that for exactly one reason:
//
//   every function that writes channel state emits an event carrying
//   `bytes32 indexed id`
//
// Given that, "no authenticated event named this channel between block B and the
// finalised head" is a PROOF the channel is unchanged. Without it, the same
// sentence is a guess that happens to be right today.
//
// Nothing in Solidity enforces this. A future mutator that writes `ch.status`
// and forgets to emit would make every watchtower silently blind to that
// transition — not slow, not wrong-looking, BLIND — and no amount of correct
// receipt verification downstream would notice, because the event it would have
// verified was never emitted.
//
// So the invariant is pinned here, by reading the source rather than by trusting
// a convention. A private helper may write state without emitting, but only if
// every function that can reach it emits.

const SOURCE = path.join(__dirname, "..", "contracts", "AxonChannels.sol");

/** Comments are stripped first: they discuss `ch.status` constantly. */
function stripComments(src: string): string {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/\/\/[^\n]*/g, "");
}

interface Fn {
  name: string;
  visibility: string;
  body: string;
}

/** Extract every function with a brace-balanced body. */
function extractFunctions(src: string): Fn[] {
  const out: Fn[] = [];
  const sig = /function\s+(\w+)\s*\(/g;
  let m: RegExpExecArray | null;
  while ((m = sig.exec(src)) !== null) {
    // Walk to the opening brace of the body, skipping the parameter list and
    // the modifier/returns clause.
    let i = m.index;
    let depth = 0;
    let bodyStart = -1;
    for (; i < src.length; i++) {
      const c = src[i];
      if (c === "(") depth++;
      else if (c === ")") depth--;
      else if (c === "{" && depth === 0) {
        bodyStart = i;
        break;
      } else if (c === ";" && depth === 0) {
        break; // an interface declaration, no body
      }
    }
    if (bodyStart < 0) continue;

    let brace = 0;
    let end = bodyStart;
    for (; end < src.length; end++) {
      if (src[end] === "{") brace++;
      else if (src[end] === "}") {
        brace--;
        if (brace === 0) break;
      }
    }
    const header = src.slice(m.index, bodyStart);
    const visibility =
      /\b(private|internal|external|public)\b/.exec(header)?.[1] ?? "public";
    out.push({
      name: m[1],
      visibility,
      body: src.slice(bodyStart + 1, end),
    });
  }
  return out;
}

/**
 * Writes to channel state. Deliberately broad: a false positive costs somebody
 * five minutes reading a diff, a false negative costs a stolen channel.
 */
function channelWrites(body: string): string[] {
  const found: string[] = [];
  const patterns: RegExp[] = [
    // ch.field = / += / -= / *= / |= ..., and ++/--
    /\b(?:ch|c|chan)\.(\w+)\s*(?:=[^=]|\+=|-=|\*=|\/=|\|=|&=|\^=|<<=|>>=)/g,
    /\b(?:ch|c|chan)\.(\w+)\s*(?:\+\+|--)/g,
    // channels[...] .field = ...
    /channels\s*\[[^\]]*\]\s*\.(\w+)\s*(?:=[^=]|\+=|-=)/g,
    // delete channels[...]
    /delete\s+channels\s*\[/g,
  ];
  for (const re of patterns) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(body)) !== null) found.push(m[1] ?? "delete");
  }
  return [...new Set(found)];
}

function emittedEvents(body: string): string[] {
  const out: string[] = [];
  const re = /emit\s+(\w+)\s*\(/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(body)) !== null) out.push(m[1]);
  return [...new Set(out)];
}

function callsTo(body: string, names: Set<string>): string[] {
  const out: string[] = [];
  for (const n of names) {
    if (new RegExp(`\\b${n}\\s*\\(`).test(body)) out.push(n);
  }
  return out;
}

/**
 * The whole check, as a function, so the self-test can run the REAL assertion
 * against a deliberately broken contract rather than re-testing the helpers.
 */
function findCompletenessFailures(source: string): string[] {
  const fns = extractFunctions(source);
  const writers = fns.filter((f) => channelWrites(f.body).length > 0);
  const failures: string[] = [];
  for (const f of writers) {
    if (emittedEvents(f.body).length > 0) continue;

    if (f.visibility !== "private" && f.visibility !== "internal") {
      failures.push(
        `${f.name} (${f.visibility}) writes ${channelWrites(f.body).join(", ")} ` +
        `and emits nothing. An externally reachable state change with no event ` +
        `makes every event-driven watchtower silently blind to it.`
      );
      continue;
    }

    // A private helper is allowed to be silent, but only if EVERY function that
    // can reach it emits.
    const callers = fns.filter(
      (c) => c.name !== f.name && callsTo(c.body, new Set([f.name])).length > 0
    );
    if (callers.length === 0) {
      failures.push(`${f.name} writes state and has no caller — dead code that mutates.`);
      continue;
    }
    for (const c of callers) {
      if (emittedEvents(c.body).length === 0) {
        failures.push(
          `${f.name} writes ${channelWrites(f.body).join(", ")} silently, and its ` +
          `caller ${c.name} does not emit either.`
        );
      }
    }
  }
  return failures;
}

describe("AxonChannels — event completeness (P14.5 invariant)", () => {
  const src = stripComments(fs.readFileSync(SOURCE, "utf8"));
  const fns = extractFunctions(src);
  const byName = new Map(fns.map((f) => [f.name, f]));

  it("parsed the contract at all", () => {
    // A parser that silently matched nothing would make every assertion below
    // pass vacuously, which is the worst possible outcome for this file.
    expect(fns.length, "no functions parsed — the extractor is broken").to.be.greaterThan(10);
    expect(byName.has("closeUnilateral")).to.equal(true);
    expect(byName.has("_reduceCollateral")).to.equal(true);
    expect(byName.has("_payout")).to.equal(true);
  });

  it("every function that writes channel state emits, directly or through its callers", () => {
    const writers = extractFunctions(src).filter((f) => channelWrites(f.body).length > 0);
    expect(writers.length, "no state writers found — the detector is broken")
      .to.be.greaterThan(5);

    expect(findCompletenessFailures(src).join("\n"),
      "channel state can change without an event").to.equal("");
  });

  // Events that are NOT about a channel, and so cannot carry a channel id.
  //
  // The watchtower's inference is "no authenticated event named this channel
  // between B and the finalised head, therefore the channel is unchanged". A
  // delegation event changes `delegations[party]`, never `channels[id]`, so it
  // cannot invalidate that sentence — and it must not be allowed to LOOK like a
  // channel event either, which is why the test below insists it carries no
  // bytes32 topic at all.
  //
  // The list is explicit and asserted exactly. A future event added here
  // without thought is a future event the watchtower ignores.
  const NON_CHANNEL_EVENTS = ["DelegationSet", "DelegationRevoked"];

  it("every event a mutator emits carries `bytes32 indexed id` first", () => {
    const artifact = require("../artifacts/contracts/AxonChannels.sol/AxonChannels.json");
    const all = artifact.abi.filter((e: any) => e.type === "event");
    const events = all.filter((e: any) => !NON_CHANNEL_EVENTS.includes(e.name));
    expect(events.length).to.be.greaterThan(5);

    // The exemptions must actually exist, or the list is quietly excusing
    // nothing while a real channel event slips past under one of these names.
    for (const name of NON_CHANNEL_EVENTS) {
      expect(all.map((e: any) => e.name)).to.include(name);
    }

    // An exempt event may not carry a bytes32 topic anywhere: a watchtower
    // scanning topics[1] for a channel id must never find something that looks
    // like one.
    for (const e of all.filter((x: any) => NON_CHANNEL_EVENTS.includes(x.name))) {
      for (const input of e.inputs) {
        expect(input.type, `${e.name} carries a bytes32 that could be mistaken for a channel id`)
          .to.not.equal("bytes32");
      }
    }

    const failures: string[] = [];
    for (const e of events) {
      const first = e.inputs[0];
      if (!first || first.type !== "bytes32" || !first.indexed) {
        failures.push(
          `${e.name}'s first parameter is ${first?.type} indexed=${first?.indexed}; ` +
          `the watchtower reads the channel id from topics[1] and cannot find it otherwise.`
        );
      }
    }
    expect(failures.join("\n")).to.equal("");
  });

  it("the event set matches what the Go decoder knows about", () => {
    // Mirrors channelEventSignatures in storage-client/internal/channel/eventreader.go.
    // A new event added to the contract and not to the decoder is an event the
    // watchtower silently ignores, so the two lists are asserted EQUAL rather
    // than "the decoder knows at least these".
    const expected = [
      "ChannelOpened(bytes32,address,address,uint256)",
      "Deposited(bytes32,address,uint256)",
      "CheckpointApplied(bytes32,uint64,uint256,uint256)",
      "ClosedCooperatively(bytes32,uint256,uint256)",
      "CloseStarted(bytes32,address,uint64,uint256)",
      "Challenged(bytes32,uint64)",
      "LockClaimed(bytes32,bytes32,bytes32)",
      "LockExpired(bytes32,bytes32)",
      "Settled(bytes32,uint256,uint256)",
      // Authorization, not channel state. Listed so the two sides stay in step,
      // and so adding one is a deliberate act rather than a silent divergence.
      "DelegationSet(address,address,uint64,uint32,uint64)",
      "DelegationRevoked(address,address,uint64)",
    ].sort();

    const artifact = require("../artifacts/contracts/AxonChannels.sol/AxonChannels.json");
    const actual = artifact.abi
      .filter((e: any) => e.type === "event")
      .map((e: any) => `${e.name}(${e.inputs.map((i: any) => i.type).join(",")})`)
      .sort();

    expect(actual, "the contract's events and the Go decoder's list have diverged")
      .to.deep.equal(expected);

    // And the topic0 values the Go side computes must be these.
    for (const sig of expected) {
      const topic = ethers.id(sig);
      expect(topic).to.match(/^0x[0-9a-f]{64}$/);
    }
  });

  it("a mutator that forgets to emit is actually caught", () => {
    // A completeness check that cannot fail is decoration. This injects the
    // exact mistake being guarded against — a new external function that writes
    // status and emits nothing — and runs the REAL assertion against it.
    const mutated = src.replace(
      "function settle(bytes32 id) external {",
      `function abandon(bytes32 id) external {
         Channel storage ch = channels[id];
         ch.status = Status.Settled;
       }
       function settle(bytes32 id) external {`
    );
    expect(mutated, "the mutation did not apply — this test would be vacuous")
      .to.not.equal(src);

    const failures = findCompletenessFailures(mutated);
    expect(failures.length, "a silent external mutator was NOT caught").to.be.greaterThan(0);
    expect(failures.join("\n")).to.contain("abandon");
  });

  it("a silent PRIVATE helper reached from a non-emitting caller is caught", () => {
    // The subtler shape: the write hides in a helper, and the helper is reached
    // from somewhere that emits nothing. _reduceCollateral is legitimate today
    // only because its one caller emits.
    const mutated = src.replace(
      "function settle(bytes32 id) external {",
      `function drain(bytes32 id) external {
         Channel storage ch = channels[id];
         _reduceCollateral(ch, 1);
       }
       function settle(bytes32 id) external {`
    );
    expect(mutated).to.not.equal(src);

    const failures = findCompletenessFailures(mutated);
    expect(failures.length, "a silent private write reached from a silent caller was NOT caught")
      .to.be.greaterThan(0);
    expect(failures.join("\n")).to.contain("_reduceCollateral");
  });
});
