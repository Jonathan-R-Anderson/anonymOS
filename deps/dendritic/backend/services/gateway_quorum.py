"""Turning validator receipts into a verdict — or refusing to.

SGVS §12 asks for agreement among independent validators before a gateway is
judged. The thresholds are the easy part. The hard part is the word
*independent*, and getting it wrong is worse than having no verdict at all: a
number computed from five machines one person owns looks exactly like
corroboration and is not, and anyone reading it would be misled in the
direction of false confidence.

So independence is MEASURED here, never assumed:

    agreement    ->  how many validators said the same thing
    independence ->  how many distinct operators and networks they represent

A verdict requires both. When the second is missing this module returns
``insufficient_independence`` and no score — which is the honest output for a
network that currently has one operator, and stays honest by itself the moment
that changes.

WHY NOT JUST COUNT VALIDATORS
-----------------------------
Because counting is exactly what an attacker controls. Running five validators
is cheap; being five unrelated people is not. If the threshold were "4 of 5
agree", the cheapest attack on any gateway would be to run five validators and
vote — and the resulting verdict would be indistinguishable from a real one.
Requiring distinct operators makes the attack cost the thing it is supposed to
cost.

WHAT A VERDICT IS NOT
---------------------
It is not a reputation score and does not feed one. `services/reputation.py`
still ignores audits entirely (see gateway_audits there). This produces a
statement about evidence — "N independent validators agree this gateway served
altered bytes" — and what to do about that is a policy decision made elsewhere,
by someone who can see the evidence.
"""

# Restated rather than imported from model.GatewayAudit, which pulls in the
# whole application: the weighing below is pure and should be testable without a
# database behind it. test_gateway_quorum asserts these still match the model's,
# so the convenience cannot quietly become a divergence.
RESULT_PASS = "pass"
RESULT_MISMATCH = "mismatch"
RESULT_STALE = "stale"
RESULT_UNSIGNED = "unsigned"

# SGVS §12 defaults. Governance parameters rather than constants: a network with
# eleven operators should be able to demand more than one with five, without a
# code change and a deploy standing between it and that decision.
DEFAULTS = {
    # How many validators must report the same result.
    "gateway_quorum_agree": 4,
    # Out of how many reporting at all.
    "gateway_quorum_of": 5,
    # How many DISTINCT OPERATORS those validators must represent. This is the
    # threshold that makes the others mean anything.
    "gateway_quorum_operators": 3,
    # ...across how many distinct network trust domains (ASN/prefix), so one
    # operator with three cheap VPS in one datacentre is not three views.
    "gateway_quorum_networks": 2,
}

VERDICT_CLEAN = "clean"
VERDICT_TAMPERED = "tampered"
VERDICT_STALE = "serving_stale"
VERDICT_UNSIGNED = "stripping_signatures"
VERDICT_INSUFFICIENT = "insufficient_evidence"
VERDICT_NOT_INDEPENDENT = "insufficient_independence"

# Which result each adverse verdict is drawn from.
_ADVERSE = {
    RESULT_MISMATCH: VERDICT_TAMPERED,
    RESULT_STALE: VERDICT_STALE,
    RESULT_UNSIGNED: VERDICT_UNSIGNED,
}


def thresholds():
    """Current governance parameters, falling back to the SGVS defaults.

    Falls back whole if settings cannot be read at all. Defaulting is safe here
    only because every default is the STRICTER choice: an unreadable setting
    makes a verdict harder to reach, never easier.
    """
    try:
        from model.SiteSetting import get_setting
    except Exception:
        return dict(DEFAULTS)

    values = {}
    for name, fallback in DEFAULTS.items():
        try:
            values[name] = int(get_setting(name, fallback) or fallback)
        except Exception:
            values[name] = fallback
    return values


def evaluate(observations, limits=None):
    """Weigh validator observations of ONE gateway at one object version.

    ``observations`` are dicts with ``result``, ``observer``, ``operator`` and
    ``network``. Returns a verdict dict; never raises, and never invents
    agreement it did not see.
    """
    limits = limits or thresholds()
    validators = [o for o in observations if o.get("kind") == "validator"]

    # Distinct VALIDATORS, not distinct reports: one validator repeating itself
    # is one opinion, and deduplication upstream should already guarantee that.
    # Enforced again here because this is the number a verdict rests on.
    by_observer = {}
    for entry in validators:
        by_observer[entry.get("observer") or ""] = entry
    unique = list(by_observer.values())

    tally = {}
    for entry in unique:
        tally[entry.get("result")] = tally.get(entry.get("result"), 0) + 1

    reporting = len(unique)
    if reporting < limits["gateway_quorum_of"]:
        return _verdict(VERDICT_INSUFFICIENT, tally, unique, limits,
                        "only %d validator(s) reported; %d are required"
                        % (reporting, limits["gateway_quorum_of"]))

    winner, agreed = None, 0
    for result, count in tally.items():
        if count > agreed:
            winner, agreed = result, count
    if agreed < limits["gateway_quorum_agree"]:
        return _verdict(VERDICT_INSUFFICIENT, tally, unique, limits,
                        "no result reached %d agreeing validators"
                        % limits["gateway_quorum_agree"])

    # The independence gate. Deliberately applied to the validators that AGREED,
    # not to everyone who reported: five validators where four share an operator
    # is one operator's claim with three witnesses of its own choosing.
    agreeing = [e for e in unique if e.get("result") == winner]
    operators = {(e.get("operator") or e.get("observer") or "") for e in agreeing}
    networks = {(e.get("network") or "") for e in agreeing if e.get("network")}
    if (len(operators) < limits["gateway_quorum_operators"]
            or len(networks) < limits["gateway_quorum_networks"]):
        return _verdict(
            VERDICT_NOT_INDEPENDENT, tally, unique, limits,
            "%d agreeing validator(s) across %d operator(s) and %d network(s); "
            "%d and %d are required. Agreement without independence is one "
            "party's claim repeated, and is reported as such rather than scored."
            % (agreed, len(operators), len(networks),
               limits["gateway_quorum_operators"], limits["gateway_quorum_networks"]),
            operators=len(operators), networks=len(networks))

    verdict = VERDICT_CLEAN if winner == RESULT_PASS else _ADVERSE.get(
        winner, VERDICT_INSUFFICIENT)
    return _verdict(verdict, tally, unique, limits,
                    "%d of %d validators agree, across %d operators and %d networks"
                    % (agreed, reporting, len(operators), len(networks)),
                    operators=len(operators), networks=len(networks))


def _verdict(verdict, tally, unique, limits, why, operators=0, networks=0):
    return {
        "verdict": verdict,
        "counts": tally,
        "validators": len(unique),
        "operators": operators,
        "networks": networks,
        "thresholds": limits,
        "why": why,
        # True only when the independence gate was actually cleared. Anything
        # reading this must branch on it rather than on the verdict string: a
        # verdict without independence is evidence, not a finding.
        "independent": verdict not in (VERDICT_NOT_INDEPENDENT, VERDICT_INSUFFICIENT),
    }


def evaluate_gateway(gateway, since=None):
    """Verdict for one gateway, from its stored validator observations."""
    from model.GatewayAudit import GatewayAudit
    from shared import db

    query = db.session.query(GatewayAudit).filter(
        GatewayAudit.gateway == gateway,
        GatewayAudit.observer_kind == "validator")
    if since is not None:
        query = query.filter(GatewayAudit.created_at >= since)

    observations = [{
        "result": row.result, "observer": row.observer, "kind": "validator",
        # Operator and network are properties of the VALIDATOR, not of this
        # report, so they are resolved from the node registry rather than taken
        # from the receipt. A receipt that could name its own operator could
        # name a different one each time and manufacture independence.
        "operator": _operator_for(row.observer),
        "network": _network_for(row.observer),
    } for row in query.all()]
    result = evaluate(observations)
    result["gateway"] = gateway
    return result


def _operator_for(observer):
    """Which operator a validator belongs to.

    Today this is the payout address: nodes paying the same wallet are one
    party's machines however many identities they hold. It is a weak signal --
    an operator wanting to look like three can use three wallets -- and it is
    the strongest one available without an identity system nobody wants. The
    weakness is the reason the network threshold exists alongside it.
    """
    from model.PofRegistration import PofPayout
    from shared import db

    if not observer:
        return ""
    row = (db.session.query(PofPayout)
           .filter(PofPayout.p2p_public_key == observer).one_or_none())
    return (row.payout or "").lower() if row is not None else observer


def _network_for(observer):
    """The validator's network trust domain, as the gateway registry sees it.

    A /24 rather than an exact address: two machines in one rack are not two
    independent views of the internet, and an operator who moves one host must
    not thereby gain an extra vote.
    """
    from services.gateway_registry import active_gateways

    if not observer:
        return ""
    gateways, _ = active_gateways()
    for entry in gateways:
        if str(entry.get("node_id") or "") == observer:
            address = str(entry.get("ip") or "")
            return ".".join(address.split(".")[:3]) if "." in address else address
    return ""
