"""A second implementation of AXON §11.3, written from the specification.

E8.3: "Two independent implementations written from the specification agree on
the corpus — falsified by any disagreement; this is the test that catches an
under-specified grammar."

Written against axon/09-naming-registry.md §11.3.1 (grammar), §11.3.2
(normalization, zone_id, nameHash) and §11.3.3 (skeleton) ONLY.  Where the
specification does not decide something, the reading taken is marked
`AMBIGUITY:` in a comment and recorded in FINDINGS.md — those comments are the
deliverable of this exercise as much as the code is.

Independence caveat, stated rather than hidden: this is one author, two
languages, spec-only.  E8.3 as written implies two authors.  See FINDINGS.md.
"""

from hashlib import sha256

from keccak import keccak256

# §11.3: "Exactly one string is a compile-time constant, stated here once."
ROOT_SUFFIX = "axon"

# §11.3.2 "off chain  zone_id = SHA-256( "AXON-zone-v1" || 0x00 || canonical )"
ZONE_ID_LABEL = "AXON-zone-v1"

# §11.3.1 length bounds.
NAMESPACE_MIN, NAMESPACE_MAX = 3, 24
REGISTRABLE_MIN, REGISTRABLE_MAX = 3, 63
SUBORDINATE_MIN, SUBORDINATE_MAX = 1, 63
NAME_MAX_BYTES = 253
MAX_LABELS = 8

# §11.3.1 refusal table: "`key`, `srv`, `local`, `test`, `invalid`, `example`,
# `axon`, and any label beginning `_`".  `axon` is spelled out there, but §11.3
# says the root suffix is the one compile-time constant and no other part of the
# spec contains that literal — so it is taken as ROOT_SUFFIX, not a 7th word.
# A label beginning `_` cannot survive step 6 anyway (`_` is outside
# [a-z0-9.-]), so that clause is unreachable; it is kept for the case where a
# caller validates a label without normalizing first.
RESERVED_BASE = frozenset({"key", "srv", "local", "test", "invalid", "example"})

ERRORS = (
    "non-ascii", "control", "empty-label", "charset", "grammar",
    "not-root", "reserved", "too-long", "too-many-labels",
)


class NameError_(Exception):
    def __init__(self, kind):
        assert kind in ERRORS, kind
        self.kind = kind
        super().__init__(kind)


def is_reserved(label, root=ROOT_SUFFIX):
    return label in RESERVED_BASE or label == root or label.startswith("_")


class Name:
    """A canonical name.  Constructed only by normalise()."""

    def __init__(self, labels, root):
        self.labels = list(labels)
        self.root = root

    def __str__(self):
        return ".".join(self.labels)

    # §11.3.1 name := subordinate* registrable "." namespace "." ROOT_SUFFIX
    def root_label(self):
        return self.labels[-1]

    def namespace(self):
        return self.labels[-2]

    def registrable(self):
        return self.labels[-3]

    def subordinates(self):
        return self.labels[:-3]

    def is_registrable(self):
        """True when nothing is delegated below the registrable label."""
        return len(self.labels) == 3

    def zone_id(self):
        # SHA-256( "AXON-zone-v1" || 0x00 || canonical_name )
        return sha256(
            ZONE_ID_LABEL.encode("ascii") + b"\x00" + str(self).encode("ascii")
        ).digest()

    def name_hash(self):
        """§11.3.2.  None for subordinate names: "Only the registrable label is
        on chain, so `nameHash` exists only for `label.axon`."""
        if not self.is_registrable():
            return None
        # nameHash = keccak256( namehash(TLD) || keccak256(label) )
        # namehash("")  = 0x00 * 32
        # namehash(TLD) = keccak256( 0x00*32 || keccak256(TLD) )
        #
        # AMBIGUITY (nameHash-parent), RESOLVED AGAINST THE SPEC TEXT: §11.3.2
        # wrote the parent as namehash(TLD), which is the pre-namespace
        # two-level form.  A canonical name always carries a namespace label
        # between the registrable label and the root, so read literally
        # alice.lab.axon and alice.corp.axon produce the SAME nameHash --
        # directly contradicting §11.3.1's "different names owned by
        # potentially different people".  The full ENS-style chain over every
        # label is what is meant and what the contract must recompute; §11.3.2
        # has been corrected to state it.  See FINDINGS.md F1.
        node = bytes(32)                       # namehash("") = 0x00 * 32
        for label in reversed(self.labels):    # root first, registrable last
            node = keccak256(node + keccak256(label.encode("ascii")))
        return node


def _valid_ldh(label):
    """§11.3.1 ldh-label plus the refusal table's hyphen rules.

    ldh-label := ALPHA-LOWER / DIGIT ( ( ALPHA-LOWER / DIGIT / "-" )* ( ALPHA-LOWER / DIGIT ) )?
    """
    if label == "":
        raise NameError_("empty-label")
    for ch in label:
        if not (("a" <= ch <= "z") or ("0" <= ch <= "9") or ch == "-"):
            # "Any byte outside [a-z0-9-] after normalization"
            raise NameError_("grammar")
    # "Leading or trailing `-`" — also what the ldh-label production says.
    if label[0] == "-" or label[-1] == "-":
        raise NameError_("grammar")
    # "`-` at both positions 3 and 4 (`xx--…`)" — 1-based positions.
    if len(label) >= 4 and label[2] == "-" and label[3] == "-":
        raise NameError_("grammar")


def _check_length(label, lo, hi):
    # AMBIGUITY (short-vs-long), RESOLVED BY CONVENTION: §11.3.1 states one
    # bound per position and the refusal table lists "Length < 3" separately.
    # The spec names no error identifiers at all, so nothing decides whether a
    # 2-character registrable label is "grammar" or "too-long".  Convention
    # adopted, and now written into §11.3.2: `too-long` is the 253-byte whole-
    # name cap ONLY; a per-label bound violation in either direction is a
    # grammar refusal, because §11.3.1's production is where the bound is
    # stated.
    if len(label) < lo or len(label) > hi:
        raise NameError_("grammar")


def normalise(input_bytes, root=ROOT_SUFFIX):
    """§11.3.2.  A total function from input to a canonical name or an error."""
    if isinstance(input_bytes, str):
        input_bytes = input_bytes.encode("utf-8", "surrogateescape")

    # 1. Reject any byte >= 0x80.
    for b in input_bytes:
        if b >= 0x80:
            raise NameError_("non-ascii")
    # 2. Reject any control byte < 0x20 or 0x7F.
    for b in input_bytes:
        if b < 0x20 or b == 0x7F:
            raise NameError_("control")

    s = input_bytes.decode("ascii")

    # 3. Strip at most one trailing ".".
    if s.endswith("."):
        s = s[:-1]

    # 4. Reject a leading "." or any empty label.
    if s.startswith("."):
        raise NameError_("empty-label")
    labels = s.split(".")
    if any(l == "" for l in labels):
        raise NameError_("empty-label")

    # 5. Map A-Z to a-z.  The ONLY character mapping performed.
    labels = [
        "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in l) for l in labels
    ]

    # 6. Reject any remaining byte outside [a-z0-9.-].
    for l in labels:
        for ch in l:
            if not (("a" <= ch <= "z") or ("0" <= ch <= "9") or ch == "-"):
                raise NameError_("charset")

    # 7. Apply 11.3.1.
    #
    # AMBIGUITY (check-order): §11.3.2 numbers its own eight steps but not the
    # checks inside step 7.  Order taken: total length, label count, per-label
    # grammar, per-label length bound, reserved.  Only the reported error kind
    # depends on it; accept/reject does not.
    # Label count before byte count: an 9-label name that is also 300 bytes is
    # reported as too-many-labels.  §11.3.1 states both bounds and orders
    # neither; convention adopted, now written into §11.3.2.
    canonical = ".".join(labels)
    if len(labels) > MAX_LABELS:
        raise NameError_("too-many-labels")
    if len(canonical.encode("ascii")) > NAME_MAX_BYTES:
        raise NameError_("too-long")
    # registrable "." namespace "." ROOT_SUFFIX is the shortest legal name.
    if len(labels) < 3:
        raise NameError_("grammar")

    # AMBIGUITY (root-is-not-a-label), RESOLVED: §11.3.1's production reads
    #   name := subordinate* registrable "." namespace "." ROOT_SUFFIX
    # so the trailing element is the CONSTANT, not an instance of the `label`
    # production, and the ldh rules do not apply to it.  Step 8's equality
    # check is the whole of its validation -- an ungrammatical trailing label
    # can only ever be "not the root suffix", and reporting it as a grammar
    # error would tell a caller to fix a label they cannot choose.
    for l in labels[:-1]:
        _valid_ldh(l)

    _check_length(labels[-2], NAMESPACE_MIN, NAMESPACE_MAX)
    _check_length(labels[-3], REGISTRABLE_MIN, REGISTRABLE_MAX)
    for l in labels[:-3]:
        _check_length(l, SUBORDINATE_MIN, SUBORDINATE_MAX)
    # The root label's own length is not bounded by §11.3.1 — it is fixed by
    # step 8 instead.

    # AMBIGUITY (reserved-scope): the reserved list sits in a table of rules
    # "enforced in AxonRegistry.register", which only ever sees the registrable
    # label and its namespace.  The root label cannot be checked at all — it
    # equals ROOT_SUFFIX, which the list names.  Subordinates are delegated off
    # chain and no registrar sees them.  Read as: registrable + namespace only.
    if is_reserved(labels[-3], root) or is_reserved(labels[-2], root):
        raise NameError_("reserved")

    # 8. Require the last label == TLD.
    if labels[-1] != root:
        raise NameError_("not-root")

    return Name(labels, root)


# §11.3.3.  The pseudocode as first written folded '1'->'l' and '0'->'o' and
# stopped there, while its own prose named `cl`~`d` and the uppercase pairs.
# The normative set is the per-pair table T8.4 requires; §11.3.3 has been
# corrected to state it, and the fold direction is onto the DIGIT (the choice
# is arbitrary for class membership but not for the stored bytes, so it has to
# be stated).  See FINDINGS.md F2.
_FOLD = {"o": "0", "l": "1", "i": "1", "s": "5", "b": "6", "g": "9", "z": "2"}


def skeleton_string(label):
    s = label
    s = s.replace("-", "")       # hyphen elision: my-bank ~ mybank
    s = s.replace("rn", "m")     # multi-character first, left to right
    s = s.replace("vv", "w")
    s = s.replace("cl", "d")
    s = "".join(_FOLD.get(c, c) for c in s)
    return s


def skeleton(label):
    """§11.3.3 returns keccak256 of the folded form."""
    return keccak256(skeleton_string(label).encode("ascii"))


def confusable(a, b):
    return skeleton_string(a) == skeleton_string(b)
