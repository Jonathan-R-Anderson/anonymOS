"""E8.3: diff the Python implementation of §11.3 against internal/axon/name.

    python3 corpus.py
    (cd ../.. && go run ./cmd/e83dump -corpus scripts/e83/corpus.json -out scripts/e83/go.json)
    python3 compare.py

Two verdicts are reported, because they answer different questions:

  BEHAVIOUR  did both accept/reject the same inputs, and for the accepted ones
             produce the same canonical form, the same parse, and the same
             hashes?  A disagreement here is a bug in one implementation or a
             hole in the grammar — E8.3's actual target.

  DIAGNOSIS  did both report the same error *kind* for the rejected ones?
             §11.3.2 orders its eight steps but not the checks inside step 7,
             so a disagreement here is under-specification, not a wrong answer.

Exit code is non-zero if BEHAVIOUR diverges.  DIAGNOSIS divergences are printed
and counted; they are findings, not failures.
"""

import base64
import json
import sys
from collections import Counter

import axonname
from keccak import keccak256

# Compared for every accepted input.  zone_id and name_hash are the ones that
# matter most: a divergence there means one name yields two DHT keys (§11.3's
# stated failure mode) or two chain identities.
BEHAVIOUR_FIELDS = [
    "canonical", "labels", "root", "namespace", "registrable",
    "subordinates", "is_registrable", "zone_id", "name_hash", "skeleton",
]


def py_result(raw):
    try:
        n = axonname.normalise(raw)
    except axonname.NameError_ as e:
        return {"err": e.kind}
    nh = n.name_hash()
    return {
        "canonical": str(n),
        "labels": n.labels,
        "root": n.root_label(),
        "namespace": n.namespace(),
        "registrable": n.registrable(),
        "subordinates": n.subordinates(),
        "is_registrable": n.is_registrable(),
        "zone_id": n.zone_id().hex(),
        "name_hash": nh.hex() if nh is not None else "",
        # The Go side returns Skeleton as a string; §11.3.3 defines it as
        # keccak256 of that string.  Compare whichever form Go emits: if it is
        # 64 hex characters it is already hashed, otherwise it is the folded
        # form and the hash is checked separately below.
        "skeleton": axonname.skeleton_string(n.registrable()),
    }


def norm_go(r):
    """Drop Go's omitempty asymmetry so absent == empty on both sides."""
    return {
        "err": r.get("err", ""),
        "canonical": r.get("canonical", ""),
        "labels": r.get("labels") or [],
        "root": r.get("root", ""),
        "namespace": r.get("namespace", ""),
        "registrable": r.get("registrable", ""),
        "subordinates": r.get("subordinates") or [],
        "is_registrable": r.get("is_registrable", False),
        "zone_id": r.get("zone_id", ""),
        "name_hash": r.get("name_hash", ""),
        "skeleton": r.get("skeleton", ""),
    }


def norm_py(r):
    return {
        "err": r.get("err", ""),
        "canonical": r.get("canonical", ""),
        "labels": r.get("labels") or [],
        "root": r.get("root", ""),
        "namespace": r.get("namespace", ""),
        "registrable": r.get("registrable", ""),
        "subordinates": r.get("subordinates") or [],
        "is_registrable": r.get("is_registrable", False),
        "zone_id": r.get("zone_id", ""),
        "name_hash": r.get("name_hash", ""),
        "skeleton": r.get("skeleton", ""),
    }


def main():
    corpus = json.load(open("corpus.json"))
    godump = json.load(open("go.json"))
    inputs = [base64.b64decode(s) for s in corpus["inputs_b64"]]
    go = godump["results"]
    if len(go) != len(inputs):
        print(f"corpus/go length mismatch: {len(inputs)} vs {len(go)}")
        return 2

    skeleton_hashed = any(
        len(r.get("skeleton", "")) == 64 and all(c in "0123456789abcdef" for c in r["skeleton"])
        and not r["skeleton"].isalpha()
        for r in go
    )

    behaviour, diagnosis = [], []
    kinds_go, kinds_py = Counter(), Counter()
    accepted = 0

    for i, raw in enumerate(inputs):
        g = norm_go(go[i])
        p = norm_py(py_result(raw))
        if skeleton_hashed and p["skeleton"]:
            p["skeleton"] = keccak256(p["skeleton"].encode()).hex()

        g_ok, p_ok = (g["err"] == ""), (p["err"] == "")
        if g_ok:
            kinds_go["<accepted>"] += 1
        else:
            kinds_go[g["err"]] += 1
        if p_ok:
            kinds_py["<accepted>"] += 1
        else:
            kinds_py[p["err"]] += 1

        if g_ok != p_ok:
            behaviour.append((i, raw, "accept/reject",
                              "accepted" if g_ok else g["err"],
                              "accepted" if p_ok else p["err"]))
            continue
        if not g_ok:
            if g["err"] != p["err"]:
                diagnosis.append((i, raw, "err", g["err"], p["err"]))
            continue

        accepted += 1
        for f in BEHAVIOUR_FIELDS:
            if g[f] != p[f]:
                behaviour.append((i, raw, f, g[f], p[f]))

    def show(rows, label, limit=25):
        print(f"\n{label}: {len(rows)}")
        seen = Counter(r[2] for r in rows)
        for field, n in seen.most_common():
            print(f"    {field}: {n}")
        for i, raw, field, gv, pv in rows[:limit]:
            print(f"  [{i}] {raw!r}\n      {field}: go={gv!r} py={pv!r}")
        if len(rows) > limit:
            print(f"  ... {len(rows) - limit} more")

    print(f"corpus: {len(inputs)} inputs, seed {corpus['seed']}, root {corpus['root_suffix']!r}")
    print(f"accepted by both: {accepted}")
    print(f"go   outcomes: {dict(kinds_go.most_common())}")
    print(f"py   outcomes: {dict(kinds_py.most_common())}")
    show(behaviour, "BEHAVIOUR divergences (E8.3 falsifiers)")
    show(diagnosis, "DIAGNOSIS divergences (error kind only — under-specification)")

    if behaviour:
        print("\nE8.3: NOT met — the implementations disagree on behaviour.")
        return 1
    print("\nE8.3: behaviour agrees on every input in the corpus.")
    if diagnosis:
        print(f"      {len(diagnosis)} error-kind divergences remain — see FINDINGS.md.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
