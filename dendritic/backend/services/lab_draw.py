"""Which machine a non-member is given this month.

Kept free of the app so it can be tested on its own, and so the rule that
decides who gets what is readable without a database in the way. It is the whole
free tier in fifteen lines.
"""

import hashlib


def free_machine_for(slip_id, period, slugs):
    """Which machine this account is given this month, if it has no membership.

    Deterministic from the account and the month rather than actually random.
    Two properties fall out of that, and both matter more than novelty: a
    refresh cannot reroll it, and nobody can be accused of the draw having been
    rigged for them, because anybody can recompute it.

    The candidate list is sorted first so the same catalogue always produces the
    same answer regardless of what order the database returned it in.
    """
    if not slugs:
        return None
    ordered = sorted(slugs)
    seed = "syndichan-free-lab:%s:%s" % (slip_id, period)
    digest = hashlib.sha256(seed.encode("utf-8")).digest()
    return ordered[int.from_bytes(digest[:8], "big") % len(ordered)]
