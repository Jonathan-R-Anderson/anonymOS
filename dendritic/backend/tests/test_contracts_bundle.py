"""The deploy console must offer exactly the contracts this project HAS.

WHY THIS TEST EXISTS
--------------------
`backend/static/pof/contracts.json` is the bundle the admin console deploys FROM,
and it was maintained by hand -- `deploy/02_channels.ts` ends with a `console.log`
telling a human to go and edit it. It drifted, and because the console is a
MAINNET deploy panel the drift was live:

  * `AxonRegistry` was absent, so the contract carrying §93's seizure machine
    could not be deployed from the panel built to deploy it (roadmap item 1.5).
  * `AxonChannels` was absent, so the rename never reached the console.
  * `ChannelManager` and `ChannelManagerV2` were still offered -- the V1 that was
    explicitly removed from `contracts/` was one click from a mainnet deployment.
  * `CryptoZombies`, a vendored tutorial contract, was deployable to mainnet.

Every one of those is the same failure: a list of deployable bytecode that
nothing checks against the source tree. So this checks it, and
`proof-of-facilitation/scripts/build-contracts-bundle.py` regenerates it.
"""

import json
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
BUNDLE = ROOT / "static" / "pof" / "contracts.json"
CONSOLE = ROOT / "templates" / "admin-contracts.html"
SOURCES = ROOT.parent / "proof-of-facilitation" / "contracts"


def _bundle():
    return json.loads(BUNDLE.read_text())


def _console():
    return CONSOLE.read_text()


def _order(html):
    m = re.search(r"const ORDER = \[(.*?)\];", html, re.S)
    assert m, "the console has no ORDER list"
    return re.findall(r'"([^"]+)"', m.group(1))


def _ctors(html):
    """Contract -> list of argument dicts, parsed out of the CTORS literal."""
    start = html.index("const CTORS = {")
    end = html.index("const ORDER =")
    body = html[start:end]
    out = {}
    for name, spec in re.findall(r"^    (\w+): \[(.*?)\],?\n(?=    [\w/]|  \};)",
                                 body, re.S | re.M):
        out[name] = re.findall(r"\{[^}]*\bn:\s*\"([^\"]+)\"", spec)
    return out


def test_bundle_matches_the_contract_sources():
    """Nothing deployable without a source file, and nothing with one missing."""
    sources = {p.stem for p in SOURCES.glob("*.sol")}
    bundled = set(_bundle())
    orphans = bundled - sources
    assert not orphans, (
        "these are deployable from the mainnet console but have NO source file "
        "in contracts/, so nobody is maintaining them: %s" % sorted(orphans))
    missing = sources - bundled
    assert not missing, (
        "these exist in contracts/ but cannot be deployed from the console; run "
        "proof-of-facilitation/scripts/build-contracts-bundle.py: %s" % sorted(missing))


def test_retired_contracts_are_not_deployable():
    """The specific four that had drifted, named so a regression is unambiguous."""
    bundle = _bundle()
    html = _console()
    for gone in ("ChannelManager", "ChannelManagerV2", "CryptoZombies"):
        assert gone not in bundle, (
            "%s was removed from contracts/ but is still deployable to MAINNET "
            "from the admin console" % gone)
        assert gone not in _order(html), (
            "%s is still offered in the console's deploy order" % gone)
    for wanted in ("AxonRegistry", "AxonChannels"):
        assert wanted in bundle, "%s is not deployable" % wanted
        assert wanted in _order(html), "%s is not offered in the console" % wanted


def test_every_offered_contract_can_actually_be_deployed():
    """An ORDER entry with no bytecode is a button that can only throw."""
    bundle = _bundle()
    for name in _order(_console()):
        assert name in bundle, (
            "the console offers %s but the bundle has no bytecode for it" % name)
        assert bundle[name]["bytecode"].startswith("0x"), name
        assert len(bundle[name]["bytecode"]) > 2, (
            "%s has empty creation bytecode; it is an interface or abstract "
            "contract and cannot be deployed" % name)


def test_constructor_forms_match_the_abi():
    """The console's argument list must match the compiled constructor.

    THIS IS THE ONE THAT CATCHES A BAD DEPLOY. A CTORS entry with the wrong
    number of arguments does not fail until an operator has connected a wallet
    and pressed Deploy, and it fails inside the ABI encoder with a message about
    types rather than about the field that is wrong.
    """
    bundle = _bundle()
    ctors = _ctors(_console())
    for name in _order(_console()):
        abi = bundle[name]["abi"]
        ctor = next((e for e in abi if e.get("type") == "constructor"), None)
        expected = len(ctor["inputs"]) if ctor else 0
        assert name in ctors, "%s is offered but has no CTORS entry" % name
        assert len(ctors[name]) == expected, (
            "%s: the console asks for %d constructor arguments and the compiled "
            "ABI takes %d -- pressing Deploy would fail inside the encoder"
            % (name, len(ctors[name]), expected))


def test_registry_quarantine_default_is_not_zero():
    """R-93.3, at the one place an operator can get it wrong.

    AxonRegistry's constructor REVERTS on a zero seizeQuarantine, because a
    deployment carrying zero would look correct and make every seizure a no-op.
    The console pre-fills the `times` array, so a zero in that default is a
    deploy that wastes gas and fails -- or worse, a number somebody edits down.
    """
    html = _console()
    m = re.search(r'n: "times".*?len: 6, def: "([^"]+)"', html)
    assert m, "AxonRegistry's times[6] default is gone or reshaped"
    values = [v.strip() for v in m.group(1).split(",")]
    assert len(values) == 6, "times[6] default has %d values" % len(values)
    assert int(values[5]) > 0, (
        "seizeQuarantine defaults to zero; AxonRegistry's constructor reverts on "
        "it (R-93.3)")


def test_bundle_is_not_stale_against_compiled_artifacts():
    """Regenerating must be a no-op, or the checked-in bundle is behind."""
    import subprocess
    script = SOURCES.parent / "scripts" / "build-contracts-bundle.py"
    if not script.exists():
        pytest.skip("generator not present")
    r = subprocess.run(["python3", str(script), "--check"],
                       capture_output=True, text=True, cwd=str(SOURCES.parent))
    assert r.returncode == 0, (
        "the checked-in bundle differs from the compiled artifacts:\n%s%s"
        % (r.stdout, r.stderr))


def test_deploy_asks_before_spending():
    """A mainnet deploy must be confirmed, and the dialog must show the args.

    The mint path has always had a `window.confirm` and deploy did not, which is
    backwards: minting is reversible by burning and a deployment is not
    reversible at all. Several constructor arguments are `immutable` in Solidity
    -- AxonChannels' challengePeriod, AxonRegistry's TERM/EPOCH/SEIZE_QUARANTINE
    -- so the moment to read them is before signing, and a dialog showing only a
    fee would be asking about the cheapest part of the decision.
    """
    html = _console()
    body = html[html.index("async function deploy(name) {"):]
    body = body[:body.index("\n  }\n")]
    assert "window.confirm(" in body, (
        "deploy() spends real ETH on mainnet with no confirmation; a misclick "
        "leaves an immutable contract on chain")
    assert "argLines" in body, (
        "the deploy confirmation does not show the constructor arguments, "
        "several of which are immutable once deployed")


def test_seizure_quarantine_clears_the_appeal_floor():
    """R-93.3a: SEIZE_QUARANTINE >= 2 x votingPeriod.

    An appeal is a governance proposal, so it costs one filing interval plus one
    full voting period to decide. If the quarantine expires first the name
    reaches RECYCLABLE and the registrar may reassign it WHILE THE APPEAL IS
    OPEN -- and once a third party holds it, a successful appeal cannot be
    honoured without taking the name from someone who did nothing wrong. The
    seizure becomes irreversible by accident of timing.

    Asserted as a RELATIONSHIP between the two console defaults, not as two
    magic numbers: raising votingPeriod alone would walk straight into that case,
    and a test pinning `2592000` would not notice.
    """
    html = _console()
    ctors = _ctors(html)
    assert "AxonGovernance" in ctors and "AxonRegistry" in ctors

    voting = re.search(r'n: "votingPeriodSeconds", k: "uint", def: "(\d+)"', html)
    times = re.search(r'n: "times".*?len: 6, def: "([^"]+)"', html)
    assert voting and times, "the console defaults moved or were reshaped"

    voting_period = int(voting.group(1))
    quarantine = int(times.group(1).split(",")[5])

    assert quarantine >= 2 * voting_period, (
        "SEIZE_QUARANTINE is %d s but votingPeriod is %d s, so a name can reach "
        "RECYCLABLE and be reassigned to a third party while its appeal is still "
        "being voted on (R-93.3a needs >= %d s)"
        % (quarantine, voting_period, 2 * voting_period))
