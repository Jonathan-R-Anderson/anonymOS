"""Deterministic corpus for E8.1 / E8.3.

Both implementations are fed the SAME bytes, so the corpus is generated once,
written to corpus.json, and committed.  Inputs are base64 so a byte that is not
valid UTF-8 (the whole point of normalisation step 1) survives the round trip
through JSON intact.

Seeded PRNG: regenerating must produce the same file, or a divergence report is
about two different corpora rather than two implementations.
"""

import base64
import json
import random
import sys

SEED = 20260819
TARGET = 10_000

ALNUM = "abcdefghijklmnopqrstuvwxyz0123456789"
LDH = ALNUM + "-"
RESERVED = ["key", "srv", "local", "test", "invalid", "example", "axon"]


def ldh(rng, n):
    """A label that satisfies the ldh-label production, by construction."""
    if n == 1:
        return rng.choice(ALNUM)
    mid = "".join(rng.choice(LDH) for _ in range(n - 2))
    return rng.choice(ALNUM) + mid + rng.choice(ALNUM)


def build():
    rng = random.Random(SEED)
    out = []

    def add(s):
        out.append(s if isinstance(s, bytes) else s.encode("utf-8", "surrogateescape"))

    # -- hand-written edges, first, so they are never crowded out ------------
    for s in [
        "", ".", "..", "...", "a", "axon", ".axon", "axon.", "a.axon",
        "alice.lab.axon", "alice.lab.axon.", "alice.lab.axon..",
        "ALICE.LAB.AXON", "Alice.Lab.Axon", "aLiCe.lAb.AxOn",
        "alice..lab.axon", ".alice.lab.axon", "alice.lab..axon",
        "alice .lab.axon", " alice.lab.axon", "alice.lab.axon ",
        "alice\t.lab.axon", "alice.lab.axon\n", "alice.lab.axon\r\n",
        "alice_bob.lab.axon", "_alice.lab.axon", "alice.lab.axon\x7f",
        "alice.lab.com", "alice.lab.onion", "alice.lab.test", "alice.lab.AXON",
        "-alice.lab.axon", "alice-.lab.axon", "al--ice.lab.axon",
        "xn--fiqs8s.lab.axon", "ab--cd.lab.axon", "abc--d.lab.axon",
        "a-b-c.lab.axon", "a--b.lab.axon", "ab.lab.axon", "abc.la.axon",
        "abc.lab.axon", "key.lab.axon", "srv.lab.axon", "alice.key.axon",
        "alice.test.axon", "example.lab.axon", "axon.lab.axon",
        "alice.lab.axon.axon", "key.axon", "www.alice.lab.axon",
        "a.b.c.alice.lab.axon", "a.b.c.d.e.alice.lab.axon",
        "a.b.c.d.e.f.alice.lab.axon",
        "mybank.lab.axon", "my-bank.lab.axon", "rnybank.lab.axon",
        "vvorld.lab.axon", "world.lab.axon", "c1own.lab.axon",
        "cl0wn.lab.axon", "0livia.lab.axon", "olivia.lab.axon",
        "alice.lab.axon.", "ALICE.LAB.AXON.",
    ]:
        add(s)

    # non-ASCII and control bytes, positioned so step order is observable
    for raw in [
        b"alic\xc3\xa9.lab.axon", b"\xc3\xa9.lab.axon", b"alice.lab.ax\xffn",
        b"alice.lab.axon\x00", b"\x00alice.lab.axon", b"alice\x01.lab.axon",
        b"alice.lab.axon\x7f", b"\x80", b"\xff\xfe",
        # both a non-ASCII byte AND an empty label: which error wins?
        b"\xc3\xa9..lab.axon", b"..\xc3\xa9.axon",
        # non-ASCII full stops (U+3002, U+FF0E, U+FF61) — step 1 must eat these
        "alice。lab.axon".encode(), "alice．lab.axon".encode(),
        "alice｡lab.axon".encode(),
        # both a control byte and non-ASCII: step 1 is first
        b"\x01\xc3\xa9.lab.axon", b"\xc3\xa9\x01.lab.axon",
    ]:
        add(raw)

    # length boundaries, exact
    for n in (1, 2, 3, 4, 23, 24, 25, 62, 63, 64):
        add(f"{'a'*n}.lab.axon")           # registrable
        add(f"alice.{'a'*n}.axon")         # namespace
        add(f"{'a'*n}.alice.lab.axon")     # subordinate
    # total-length boundary: 253 and 254 bytes
    for total in (252, 253, 254):
        # k labels of 63 + tail ".lab.axon"
        tail = ".lab.axon"
        head_len = total - len(tail)
        head = []
        while head_len > 0:
            take = min(63, head_len)
            head.append("a" * take)
            head_len -= take + 1
            if head_len > 0:
                pass
        add(".".join(head) + tail)
    # label-count boundary: 7, 8, 9 labels
    for k in (6, 7, 8, 9, 10):
        add(".".join(["sub"] * (k - 3) + ["alice", "lab", "axon"]))

    # -- generated bulk ------------------------------------------------------
    while len(out) < TARGET:
        pick = rng.random()
        reg_len = rng.choice([1, 2, 3, 3, 4, 8, 20, 62, 63, 64])
        ns_len = rng.choice([1, 2, 3, 3, 5, 24, 25, 30])
        reg, ns = ldh(rng, reg_len), ldh(rng, ns_len)
        nsub = rng.choice([0, 0, 0, 1, 1, 2, 3, 5, 6])
        subs = [ldh(rng, rng.choice([1, 2, 4, 9, 63])) for _ in range(nsub)]
        root = rng.choice(["axon", "axon", "axon", "axon", "AXON", "com", "ax0n", "axonn"])
        name = ".".join(subs + [reg, ns, root])

        if pick < 0.10:                                  # case perturbation
            name = "".join(c.upper() if rng.random() < 0.4 else c for c in name)
        elif pick < 0.16:                                # reserved somewhere
            parts = name.split(".")
            parts[rng.randrange(len(parts))] = rng.choice(RESERVED)
            name = ".".join(parts)
        elif pick < 0.22:                                # hyphen abuse
            parts = name.split(".")
            i = rng.randrange(len(parts))
            style = rng.randrange(4)
            if style == 0:
                parts[i] = "-" + parts[i]
            elif style == 1:
                parts[i] = parts[i] + "-"
            elif style == 2:
                parts[i] = parts[i][:2] + "--" + parts[i][2:]
            else:
                parts[i] = "-"
            name = ".".join(parts)
        elif pick < 0.27:                                # stray dot
            i = rng.randrange(len(name) + 1) if name else 0
            name = name[:i] + "." + name[i:]
        elif pick < 0.31:                                # illegal ASCII byte
            i = rng.randrange(len(name))
            name = name[:i] + rng.choice("_ +/@!*~,:;\\'\"()[]{}<>=?%$#&|^`") + name[i + 1:]
        elif pick < 0.34:                                # non-ASCII byte
            b = bytearray(name.encode())
            b[rng.randrange(len(b))] = rng.randrange(0x80, 0x100)
            add(bytes(b))
            continue
        elif pick < 0.36:                                # control byte
            b = bytearray(name.encode())
            b[rng.randrange(len(b))] = rng.choice(list(range(0x00, 0x20)) + [0x7F])
            add(bytes(b))
            continue
        elif pick < 0.39:                                # trailing dots
            name = name + "." * rng.choice([1, 1, 2, 3])
        elif pick < 0.42:                                # confusable-rich label
            frag = rng.choice(["rn", "vv", "cl", "0", "1", "-", "m", "w", "d", "o", "l"])
            parts = name.split(".")
            parts[0] = (parts[0] + frag)[:63] or "a"
            name = ".".join(parts)

        add(name)

    return out


def main():
    corpus = build()
    payload = {
        "seed": SEED,
        "root_suffix": "axon",
        "count": len(corpus),
        "inputs_b64": [base64.b64encode(x).decode() for x in corpus],
    }
    with open("corpus.json", "w") as fh:
        json.dump(payload, fh, indent=0)
        fh.write("\n")
    print(f"corpus.json: {len(corpus)} inputs (seed {SEED})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
