#!/usr/bin/env python3
"""Generate OUTSTANDING.md — the ordered list of work left.

    python3 roadmap/build-outstanding.py           # regenerate
    python3 roadmap/build-outstanding.py --check    # non-zero if stale

FORMAT RULE: one line per item, and the line has to fit on a screen. An earlier
version of this file gave every item a paragraph of justification and became
unreadable at 56 items — the reasoning belongs in the roadmap section the item
points at, not in the list you plan from. `Ref` is where to go for the why.

Items are ordered by TRACK, and tracks are ordered by what unblocks the most.
`Blocked by` is the only dependency column: empty means it can start today.
"""

import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent / "OUTSTANDING.md"

# (id, item, blocked_by, ref)  — `item` must be ONE short line.
TRACKS = [
    ("1", "Get on chain", "All 11 deployed on ETH mainnet 2026-08-21. DEPLOYED != WIRED: the seed/role txns below still need the wallet.", [
        ("1.1",  "**DONE** — verified live on the server",                  "",        "model/Slip.py"),
        ("1.2",  "**DONE** — set via bind-mounted `.env`; no k8s here",     "",        "H2"),
        ("1.3",  "**DONE** — console live; offers the real 11-contract set","",        "H3"),
        ("1.4",  "**DONE** — AxonToken 0x8196c5..5e88, mainnet",            "",        "A1"),
        ("1.5",  "**DONE** — AxonRegistry 0x5B2D1c..f0DB, mainnet",         "",        "A2"),
        ("1.6",  "**DONE** — StakeVault 0x41988C..64a7, mainnet",          "",        "A4"),
        ("1.7",  "**DONE** — NodeRegistry 0x23B2Ea..De1A, mainnet",        "",        "A3"),
        ("1.8",  "**DONE** — Epoch/Reward/Treasury/Dispute/Keeper, mainnet","",        "A5"),
        ("1.9",  "**DONE** — AxonGovernance 0xaBA3b4..436a, mainnet",       "",        "G8 / H6"),
        ("1.10", "Write the registrar",                                      "",        "A2"),
        ("1.11", "`setGovernor()` on the registry (a wallet txn)",           "",        "H8"),
        ("1.12", "Seed supply: setTreasury + mintGenesis + closeGenesis",   "",        "A1"),
        ("1.13", "Role wiring: setDisputeManager/setSlasher/setAggregator", "",        "A5"),
        ("1.14", "Arm the genesis epoch, then settle epochs",               "1.13",    "A5"),
    ]),
    ("2", "Wire what is built but reaches nothing", "Code exists, tests pass, nothing calls it.", [
        ("2.1",  "**DONE** — updater verifies signed commits, fail-closed",  "",        "§18.14"),
        ("2.2",  "Sign `main`\'s commits + pin `SYNDICHAN_ALLOWED_SIGNERS`",  "2.1",     "§18.14"),
        ("2.2b", "**DONE** — index signed + serial; verified against origin key", "",   "§18.14"),
        ("2.3",  "**DONE** — domains populated from live connections",       "",        "T12.2 / §10"),
        ("2.3b", "Domains are empty while peers are reached over I2P",        "2.9",     "T12.2 / §10"),
        ("2.4",  "**PARTIAL** — ChainReader built; node wiring + live client next", "", "E10.4 / A7"),
        ("2.5",  "**DONE** — reads stateOf(8)+domainKey, solc-pinned, verified", "",   "H9"),
        ("2.5b", "Offline end-to-end proof test needs a ProveMPT extractor", "",        "H9"),
        ("2.6",  "Implement `peer.OperatorResolver` against `NodeRegistry`", "1.7",     "E2"),
        ("2.7",  "Call `sybil.AdmitStore`; retire the coordinator lease",    "1.6",     "E14.2 / A6"),
        ("2.8",  "Enforce the bond floor in `path.Selector.admissible`",     "1.6",     "E8"),
        ("2.9",  "Swap storage onto the AXON transport",                     "5.2",     "T11.1 / E5"),
        ("2.10", "**PARTLY DONE** — circuit binding + refusals built",       "",        "R4(b) / §7"),
        ("2.10b", "FIND_NODE wire protocol over a circuit → R4(b) met",       "5.2",     "R4(b) / P23"),
        ("2.11", "**DONE** — publish loop; T7.5 + E7.3 hold, transport injected", "", "T7.5 / E7"),
        ("2.11b", "Overlap is one-way: a fast clock has no descriptor at a boundary", "", "T7.5 / §9.4"),
        ("2.12", "Enable M2 datagram padding (needs QUIC datagram mode)",    "2.9",     "E4"),
        ("2.13", "Delete `internal/i2p` — 9 files still import it",          "2.9",     "E16.2 / G1"),
    ]),
    ("3", "Build next", "Ordered by the Part X sequence.", [
        ("3.1",  "**DONE** — G1 content identity; E-G1 holds",              "",        "§85"),
        ("3.2",  "**DONE** — G2 signed labels; E-G2 holds both halves",     "",        "§86"),
        ("3.3",  "**DONE** — G3 policy engine; E-G3 holds, no relay API",   "",        "§87"),
        ("3.4",  "**DONE** — G4 report record class; E-G4 holds",           "",        "§89"),
        ("3.5",  "G9 — `domainState`/`tldState` read path",                  "1.11",    "§93"),
        ("3.6",  "G18 — emergency quarantine",                               "3.5",     "§93"),
        ("3.7",  "G14 — host/relay offer market",                            "1.4",     "§95"),
        ("3.8",  "**DONE** — G5 report weighting; E-G5 holds, sublinear",  "",        "§90"),
        ("3.9",  "**DONE** — G11 host ranking; R-92.2 holds, reorder only", "",        "§95"),
        ("3.10", "**PARTIAL** — P6a built; scheme still [NEEDS RESEARCH]", "",        "PAR-16"),
        ("3.11", "Token purchase page + link from node management",          "1.4",     "H4"),
        ("3.12", "Spending: domain registration, TLD proposals",             "1.10",    "H5"),
        ("3.13", "**DONE** — fresh install verified; F1 was 89 missing tables", "",       "F1"),
        ("3.14", "**DONE** — PCP built (RFC 6887); mapping not wired to cmd/", "",        "F3"),
        ("3.15", "**DONE** — F4; §6.2 pool of 8 unachievable, measured 2", "",        "F4"),
    ]),
    ("4", "Missing harness", "One build discharges several criteria at once.", [
        ("4.1",  "**PARTLY DONE** — 7/7 targets reproducible locally",       "",        "§6"),
        ("4.1b", "Same-commit build on a 2nd machine/toolchain → T2.6",       "",        "§6"),
        ("4.1c", "Capture QUIC Initials + compare → T13.1/E13.1",            "4.1b",    "§16.8"),
        ("4.2",  "`axon-lab` fleet → E4.1, E6.2, E6.3, T6.6, live M1",       "",        "C2"),
        ("4.3",  "Controlled-RTT link → E2.2",                               "4.2",     "C3"),
        ("4.4",  "**DONE** — 10 min, 10.29M cells, zero loss, 135.0 Mbit/s", "",        "C5"),
        ("4.4b", "**DONE** — split SLA from regression; 2 floors, asserted",  "4.4",     "E5.2"),
        ("4.4c", "Deployment throughput SLA: needs a network, RTT, target app", "6.1",    "E5.2"),
        ("4.5",  "`MeasurePoW` on low-end hardware → T14.5",                 "",        "C6"),
        ("4.6",  "**DONE** — E8.3; 2nd impl found 2 defects + 5 gaps",       "",        "C4 / PAR-14"),
        ("4.7",  "E16.3 on all three release platforms",                     "4.1",     "G3"),
        ("4.8",  "**DONE** — T16.2; cache holds peers, never the coord key",  "",        "G4"),
        ("4.8b", "Drop `CoordinatorPublicKey`: leases AND revocations use it",  "2.7",     "G4"),
        ("4.9",  "**DONE** — T16.3 audit; found + fixed an IP leak in Detail", "",       "G5"),
        ("4.9b", "**DONE** — guard examined 0 pkgs; now fails, 3 injections",  "",        "G5"),
        ("4.9c", "**DONE** — audited by file; my leak claim was overstated",    "",        "G5"),
        ("4.9d", "**DONE** — `-race` was never running; 24 races in one harness", "",       "G5"),
        ("4.11", "**DONE** — 78 fails to 5; the last 4 are 4.12, 1 is local",  "",        "H3"),
        ("4.14", "**DONE** — /how-it-works 500 in prod, found + fixed",   "",        "H3"),
        ("4.15", "**DONE** — index-greeting drift: local run read a stale copy", "",     "H3"),
        ("4.16", "**DONE** — slip deletion saw 16 of 61 FK tables in prod",  "",        "H3"),
        ("4.17", "**DONE** — POST /federation/request 500 after writing a row", "",     "H3"),
        ("4.18", "**DONE** — stale test demanded refusing Ethereum purchases", "",      "H3"),
        ("4.19", "**DONE** — CryptoZombies removed; 2nd solc compiler gone", "",       "H3"),
        ("4.20", "Rebuild the image: `docker cp` reverts on recreate",    "",        "H3"),
        ("4.21", "`media-s3-migration` thread dies on a gevent contextvars error", "",   "H3"),
        ("4.13", "**DONE** — 55 retired reversibly, 14 were never orphans",  "",        "H3"),
        ("4.13b", "**DONE** — all 15 triaged; 1 live defect fixed, 3 stale",  "",        "H3"),
        ("4.13c", "**DONE** — 1 stale entry, not 2; checked before removing",  "",        "H3"),
        ("4.13e", "**DONE** — all 56 repaired; baseline is now zero",         "",        "H3"),
        ("4.13f", "Should the reached-by-nobody admin routes be deleted?",      "",        "H3"),
        ("4.13d", "`parse_ports` regex path ran in prod; PyYAML is undeclared", "",        "H3"),
        ("4.12", "**PARTIAL** — 9 to 7; leak contained, victim now immune",   "",        "H3"),
        ("4.10", "**DONE** — E16.4 drill run; 4 findings, incl. a false 'safe'", "",     "E16.4 / G7"),
        ("4.10b", "**DONE** — contain.List; deny+sweep, survives the restart",  "",        "E16.4 / G7"),
        ("4.10e", "**DONE** — bootstrap consults containment; 2 ids per host",  "",        "E16.4 / G7"),
        ("4.10f", "**DONE** — DenyAll + ContainmentIDs; one call, all or nothing", "",   "E16.4 / G7"),
        ("4.10c", "**DONE** — path.Source owns Candidates; reports why it is thin", "",   "E16.4 / G7"),
        ("4.10d", "**READY TO RUN** — drill scripted; needs an operator + 90 min", "",     "E16.4 / G7"),
    ]),
    ("5", "Research", "No known answer. `[NEEDS RESEARCH]` or `[UNSOLVED]`.", [
        ("5.1",  "**EVALUATED** — windows bind above ~110ms; P5b unbuilt", "",        "D2"),
        ("5.2",  "**CHARACTERISED** — needs acked state, not just a ratchet","",       "D3"),
        ("5.2b", "T7.2 needs a 'stated bound' for migration; none exists", "5.2",     "T7.2"),
        ("5.3",  "**CHARACTERISED** — 2 real gaps; the list was wrong",   "",        "D4"),
        ("5.4",  "**PARTIAL** — schedule shape built; LENGTH needs payers",  "",        "D5"),
        ("5.5",  "P14 bond calibration",                                     "1.4",     "D6"),
        ("5.6",  "DAO voting weight — 3 of 4 inputs unmeasurable",           "1.6, 1.8", "F-94.1 / H7"),
        ("5.7",  "**DONE** — R-93.3a: floor is 2 x votingPeriod, derived",  "",        "R-93.3"),
        ("5.8",  "**CHARACTERISED** — needs a 2nd view, not a better test", "",        "D7"),
        ("5.9",  "Classification engine — no corpus, adversarial inputs",    "3.2",     "§91"),
        ("5.10", "**DONE** — G6/G7 built + tested; publishing refused by test", "",   "§88"),
        ("5.10b", "G17 must land before any attestation is published (R-97.1)", "",     "§96"),
        ("5.11", "**UNBLOCKED** — R-97.1 broke the G6/G17 cycle",       "",        "§96"),
        ("5.12", "G16 Sybil resistance for governance",                      "1.6",     "§97"),
        ("5.13", "G19 cross-network governance interop",                     "1.9",     "§97"),
        ("5.14", "§12.4a policy numbers (levy decay curve)",                 "1.5",     "A8"),
        ("5.15", "TLD-proposal governance is undesigned",                    "1.9",     "H5"),
    ]),
    ("6", "Will not close by building", "PAR-15. Listed so it is never mistaken for a task.", [
        ("6.1",  "9 nodes, none carrying anonymous traffic",                 "",        "PAR-15"),
        ("6.2",  "Zero external review",                                     "",        "PAR-15"),
        ("6.3",  "Three adversarial review passes never run",                "",        "B5"),
        ("6.4",  "Live traffic still uses I2P",                              "2.13",    "B2"),
        ("6.5",  "E12.3 measured against synthetic relays",                  "6.1",     "B3"),
        ("6.6",  "Token anonymity set is zero — no payers",                  "6.1",     "B4"),
        ("6.7",  "Prune-record compliance is unobservable",                  "",        "R-93.5"),
    ]),
]


def _done(item_text):
    """An item is complete when its text says so. The status lives in the text
    because that is what a reader sees; deriving it here keeps the two from
    disagreeing."""
    return "**DONE**" in item_text


def _status():
    """id -> done?, across every track."""
    return {iid: _done(item) for _t, _n, _s, items in TRACKS
            for iid, item, _b, _r in items}


def _blockers(raw):
    return [b.strip() for b in raw.split(",") if b.strip()]


def actionable(item, done):
    """Can this be started today?

    An item is actionable when it is not finished AND every blocker it names is
    finished. THE ORIGINAL COUNT ASKED ONLY WHETHER THE COLUMN WAS EMPTY, which
    understates the answer: an item blocked solely by something that has since
    been completed is available now, and five were sitting in that state --
    1.4, 1.7, 2.2, 4.4b and 5.9 -- while the header advertised them as blocked.
    A plan file that reports the wrong ready set is wrong about the only
    question it is asked.
    """
    iid, text, blocked, _ref = item
    if _done(text):
        return False
    return all(done.get(b, False) for b in _blockers(blocked))


def render_blocked(blocked, done):
    """Blockers, with the finished ones marked rather than hidden."""
    bs = _blockers(blocked)
    if not bs:
        return "—"
    return ", ".join(b + (" ✓" if done.get(b, False) else "") for b in bs)


def render():
    done = _status()
    n = sum(len(items) for _, _, _, items in TRACKS)
    ready = sum(1 for _, _, _, items in TRACKS for i in items
                if actionable(i, done))
    out = [
        "# AXON — what is left",
        "",
        "**Generated by `roadmap/build-outstanding.py`. Do not edit by hand.**",
        "",
        f"{n} items. Tracks are ordered by what unblocks the most.",
        f"**{ready} items can start today** — nothing unfinished blocking them.",
        "A blocker marked ✓ is already complete, so the item it names is free.",
        "`Ref` points at the roadmap section or criterion with the reasoning.",
        "",
        "| Track | | Items | Ready |",
        "|---|---|---|---|",
    ]
    for tid, title, _sub, items in TRACKS:
        r = sum(1 for i in items if actionable(i, done))
        out.append(f"| **{tid}** | {title} | {len(items)} | {r} |")
    out += ["", "### Start here", "",
            "**Two keystones gate most of what is left, and neither is code.**",
            "",
            "1. **1.4** `AxonToken` — a deploy, needing a funded wallet. Unblocks",
            "   1.5, 1.6, 1.8, 1.9, and through them 2.4–2.8, 3.7, 3.11, 5.5, 5.6,",
            "   5.12, 5.14. Nothing in track 2 that touches the chain moves first.",
            "2. **5.2** the session layer (P23) — research, not construction. AXON",
            "   carries cells and has no byte stream, so 2.9 cannot start, and",
            "   2.3b, 2.10b, 2.12, 2.13 and 6.4 sit behind 2.9.",
            "",
            "Then, and independently:",
            "",
            "3. **2.2** — the verifier is built and its accept path is tested with",
            "   real signatures. It needs a signing key and a pin, nothing else.",
            "4. **4.1b** — builds are reproducible on one machine; T2.6 needs a",
            "   second machine or a CI runner to be claimable at all.",
            "5. **4.13f / 4.10d / 2.11b** — three decisions, each a few minutes of",
            "   somebody's judgement rather than a piece of work.",
            "", "---", ""]

    for tid, title, sub, items in TRACKS:
        out.append(f"## {tid}. {title}")
        if sub:
            out += ["", f"*{sub}*"]
        out += ["", "| # | Item | Blocked by | Ref |", "|---|---|---|---|"]
        for iid, item, blocked, ref in items:
            out.append(f"| {iid} | {item} | {render_blocked(blocked, done)} | {ref} |")
        out.append("")
    return "\n".join(out) + "\n"


def main(argv):
    text = render()
    if "--check" in argv:
        if not OUT.exists() or OUT.read_text() != text:
            print(f"{OUT} is STALE — run: python3 {Path(__file__).name}")
            return 1
        print(f"{OUT} is current")
        return 0
    OUT.write_text(text)
    n = sum(len(i) for _, _, _, i in TRACKS)
    print(f"wrote {OUT}: {n} items in {len(TRACKS)} tracks")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
