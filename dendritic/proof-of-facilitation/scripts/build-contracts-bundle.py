#!/usr/bin/env python3
"""Generate backend/static/pof/contracts.json from Hardhat artifacts.

WHY THIS EXISTS
---------------
The bundle was maintained BY HAND. `deploy/02_channels.ts` ends with a
`console.log` reading "Add to backend/static/pof/contracts.json so the admin
console shows it", and that instruction is the entire mechanism. It drifted, and
the drift was not cosmetic -- the admin panel is a MAINNET DEPLOY CONSOLE, so
what the bundle contains is exactly what an operator can put on chain:

  * AxonRegistry was ABSENT, so the registry carrying 93's whole seizure
    machine could not be deployed from the panel at all. It is roadmap item 1.5.
  * AxonChannels was ABSENT, so the rename never reached the console.
  * ChannelManager and ChannelManagerV2 were STILL PRESENT -- the V1 that was
    explicitly retired remained one click from a mainnet deployment.
  * CryptoZombies, a tutorial contract, was deployable to mainnet.

A hand-maintained list of deployable bytecode is a list that is wrong the moment
somebody forgets a step, and "somebody forgets a step" is not hypothetical here:
it had already happened four times.

WHAT IT REFUSES TO DO
---------------------
It will not emit a contract that has no source file in `contracts/`. That single
rule catches all four cases above: the source directory is this project's
statement of what it HAS, and a bundle entry without one is bytecode nobody is
maintaining.
"""

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
ARTIFACTS = ROOT / "artifacts" / "contracts"
SOURCES = ROOT / "contracts"
OUT = ROOT.parent / "backend" / "static" / "pof" / "contracts.json"


def main(check_only: bool) -> int:
    sources = sorted(p.stem for p in SOURCES.glob("*.sol"))
    if not sources:
        print("no sources under %s" % SOURCES, file=sys.stderr)
        return 2

    bundle = {}
    missing = []
    for name in sources:
        art = ARTIFACTS / ("%s.sol" % name) / ("%s.json" % name)
        if not art.exists():
            missing.append(name)
            continue
        a = json.loads(art.read_text())
        code = a.get("bytecode", "")
        if not code or code == "0x":
            # An interface or abstract contract compiles to no creation
            # bytecode. Emitting it would put an undeployable entry in a deploy
            # console, which is a button that can only fail.
            continue
        bundle[name] = {"abi": a["abi"], "bytecode": code}

    if missing:
        print("NOT COMPILED (run `npx hardhat compile`): " + ", ".join(missing),
              file=sys.stderr)
        return 2

    new = json.dumps(bundle, indent=2, sort_keys=True) + "\n"
    old = OUT.read_text() if OUT.exists() else ""

    if check_only:
        if new != old:
            print("%s is STALE. Run: python3 scripts/build-contracts-bundle.py" % OUT,
                  file=sys.stderr)
            prev = set(json.loads(old)) if old else set()
            for gone in sorted(prev - set(bundle)):
                print("  would REMOVE %s" % gone, file=sys.stderr)
            for added in sorted(set(bundle) - prev):
                print("  would ADD    %s" % added, file=sys.stderr)
            return 1
        print("%s is current (%d contracts)" % (OUT, len(bundle)))
        return 0

    OUT.write_text(new)
    print("wrote %s: %d contracts" % (OUT, len(bundle)))
    for name in sorted(bundle):
        print("  %-24s %6d bytes" % (name, len(bundle[name]["bytecode"]) // 2))
    return 0


if __name__ == "__main__":
    sys.exit(main("--check" in sys.argv))
