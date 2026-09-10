"""How much AXON exists, and how much of it is actually in people's hands.

WHAT "CIRCULATING" MEANS HERE, BECAUSE THE WORD IS ABUSED
---------------------------------------------------------
Circulating = total supply MINUS everything still held by the project's own
contracts. Tokens sitting in the Treasury are minted but unsold; tokens sitting
in the RewardDistributor are minted but unclaimed. Neither is in anybody's
hands, and counting them as circulating would overstate the float by whatever
has not been distributed yet — which right now is essentially all of it.

That is the number most projects quietly get wrong in the flattering direction.
Stating the deduction explicitly is the point: the page shows what is held back
and by which contract, so the figure can be checked rather than believed.

EVERY NUMBER IS READ FROM THE CHAIN
------------------------------------
Nothing here is stored, cached in a setting, or configured. A supply figure the
site remembers is one that can disagree with the chain, and on the one page
where somebody is deciding whether to trust the token, a stale number is worse
than no number. If the chain cannot be read the page says so rather than
showing the last thing it knew.
"""

from services import pof_chain

# Contracts whose holdings are NOT circulating. Named rather than inferred: a
# balance held by a contract this list forgets would be silently counted as
# somebody's, which is the error that flatters.
CUSTODIAL = ("Treasury", "RewardDistributor", "StakeVault")


def _balance_of(token, holder):
    data = "0x70a08231" + holder[2:].rjust(64, "0")
    raw = pof_chain._rpc("eth_call", [{"to": token, "data": data}, "latest"])
    return int(raw or "0x0", 16)


def supply():
    """Total, custodial and circulating, in wei plus whole tokens.

    Raises ChainError if the chain cannot be read — the caller decides what to
    show, and "unknown" is a legitimate thing for a page to say.
    """
    addresses = pof_chain.pof_addresses()
    token = pof_chain.token_address()
    if not token:
        raise pof_chain.ChainError("no token address configured")

    total = int(pof_chain._rpc(
        "eth_call", [{"to": token, "data": "0x18160ddd"}, "latest"]) or "0x0", 16)

    held = {}
    for name in CUSTODIAL:
        address = addresses.get(name)
        if not address:
            continue
        try:
            amount = _balance_of(token, address)
        except Exception:
            # One unreadable contract must not lose the whole figure, but it
            # would silently inflate "circulating" — so it is recorded as
            # unknown and the caller is told the total is not exact.
            held[name] = None
            continue
        if amount:
            held[name] = amount

    known = sum(v for v in held.values() if v)
    circulating = max(total - known, 0)
    exact = not any(v is None for v in held.values())

    return {
        "total_wei": total,
        "total": total // 10 ** 18,
        "circulating_wei": circulating,
        "circulating": circulating // 10 ** 18,
        "held": {k: (v // 10 ** 18 if v else v) for k, v in held.items()},
        "held_total": known // 10 ** 18,
        # Percentage of what EXISTS, not of some cap — a cap is a ceiling on
        # what may ever be minted, and dividing by it makes a fully distributed
        # supply look like a fifth of one.
        "circulating_pct": round(circulating * 100.0 / total, 2) if total else 0.0,
        "held_pct": round(known * 100.0 / total, 2) if total else 0.0,
        "exact": exact,
    }


def summary():
    """supply(), or a dict saying plainly that it could not be read."""
    try:
        data = supply()
        data["ok"] = True
        return data
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:200]}


# How long a cached supply figure is served for. Short enough that the front
# page is not misleading, long enough that a burst of traffic is one RPC call
# rather than thousands.
CACHE_SECONDS = 300
_CACHE_KEY = "token_supply_summary"


def cached_summary(refresh=False):
    """The supply figures WITHOUT touching the chain on this request.

    The front page is cached and must not do network I/O. This project has
    already taken an outage from putting a slow fetch inside a page render —
    GET / hung on an inline sync and the whole site went dark while every other
    route stayed fine, which made it look like a network problem rather than a
    render problem.

    So: read the cache, and if there is nothing there return None. The page
    shows nothing rather than waiting. Populating is somebody else's job —
    `refresh=True` from a page that can afford to block (the AXONCoins page,
    which already reads the chain for a balance), or a background sweep.

    A stale-but-recent number is the right trade here. A supply figure five
    minutes old is honest; a front page that hangs is not.
    """
    import json as _json

    import cache as _cache

    import time as _time

    store = _cache.Cache()
    if not refresh:
        try:
            raw = store.get(_CACHE_KEY)
            payload = _json.loads(raw) if raw else None
        except Exception:
            return None
        if not payload:
            return None
        # Expiry is carried IN the value: this Cache has no TTL argument, and a
        # figure with no age is one that can be served indefinitely after the
        # chain has moved on.
        if _time.time() - payload.get("cached_at", 0) > CACHE_SECONDS:
            return None
        return payload.get("data")

    data = summary()
    if data.get("ok"):
        try:
            store.set(_CACHE_KEY, _json.dumps({"cached_at": _time.time(), "data": data}))
        except Exception:
            # A cache that will not accept the value is not a reason to fail the
            # page that just computed it.
            pass
    return data
