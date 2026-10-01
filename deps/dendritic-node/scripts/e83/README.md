# E8.3 — a second implementation of §11.3

> E8.3: *"Two independent implementations written from the specification agree
> on the corpus — falsified by any disagreement; this is the test that catches
> an under-specified grammar."* — §11.3 exit criteria, roadmap `axon/16-roadmap.md`

`internal/axon/name` is the first implementation. This directory is the second:
Python, written from `axon/09-naming-registry.md` §11.3.1–§11.3.3 alone, with
its own keccak-256 so that not even the hash is shared.

| File | What it is |
|---|---|
| `keccak.py` | keccak-256 from FIPS-202, self-tested against published vectors. Not `hashlib.sha3_256`, which is the other padding. |
| `axonname.py` | The second implementation: grammar, normalization, `zone_id`, `nameHash`, skeleton. |
| `corpus.py` | Generates `corpus.json` — 10 000 inputs, seeded, base64 so non-UTF-8 bytes survive. |
| `../../cmd/e83dump` | Feeds the corpus through the **Go** implementation. Contains no naming logic of its own. |
| `compare.py` | Diffs the two and reports. |
| `FINDINGS.md` | **What the comparison found.** The point of the exercise. |

## Running it

```sh
nix shell nixpkgs#go nixpkgs#python3 --command scripts/e83/run.sh
```

Current result: **10 000/10 000 agree** on accept/reject, canonical form, parse,
`zone_id`, `nameHash`, skeleton, and reported error kind.

They did not agree on the first run. See `FINDINGS.md`.

## What this does and does not discharge

E8.3 as written implies two *authors*. This is one author, two languages,
spec-only — the Python was written before any of the Go source was read beyond
its exported signatures. That is the strongest form available here and it is
weaker than the criterion asks for; it is recorded rather than rounded off.
A genuinely independent implementation remains PAR-14 / P21's deliverable, and
this harness is what such an implementation would be run against.

The divergences found are pinned as Go tests (`TestE83SecondImplementation` in
`internal/axon/name/name_test.go`), so a regression is caught by the ordinary
suite without re-running the cross-check.
