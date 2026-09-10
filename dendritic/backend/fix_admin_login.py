"""Diagnose and repair admin MetaMask sign-in. Run it on the server.

    kubectl exec -n maniwani deploy/maniwani -- python fix_admin_login.py
    kubectl exec -n maniwani deploy/maniwani -- python fix_admin_login.py --repair

WHY THIS EXISTS
---------------
The operator reported `"Session creation failed; check server logs"` from
/admin/login. That message means the signature verified and the recovered
address matched the configured admin wallet — the failure is in the WRITE that
follows, and the advice it gives is useless to the one person who needs it,
because the logs are behind the dashboard they cannot reach.

The code fix is in the repository and is not deployed. This script needs no
deploy: it runs against the same database with the same models and reports
exactly which step fails, then repairs it in place if asked.

It is READ-ONLY unless given --repair, and it prints every change before making
it.
"""

import sys
import traceback

from shared import app, db


def _hr(title):
    print("\n" + title)
    print("-" * len(title))


def diagnose(repair=False):
    from model.Profile import Profile
    from model.Slip import (
        AUTH_MODE_EITHER,
        AUTH_MODE_PASSWORD,
        WALLET_ADMIN_SLIP_NAME,
        Slip,
        configured_admin_wallet_address,
        normalize_wallet_address,
        slip_auth_mode,
        slip_for_wallet,
    )

    problems = []
    fixes = []

    _hr("1. Configured admin wallet")
    configured = configured_admin_wallet_address()
    from_config = app.config.get("ADMIN_WALLET_ADDRESS")
    print("   ADMIN_WALLET_ADDRESS =", from_config or "(unset)")
    print("   effective address    =", configured)
    if not from_config:
        problems.append(
            "ADMIN_WALLET_ADDRESS is unset, so the hardcoded "
            "DEFAULT_ADMIN_WALLET_ADDRESS is in force. Anyone deploying this "
            "image gets the same admin wallet. Set it in the configmap."
        )

    _hr("2. The wallet-admin slip")
    by_wallet = slip_for_wallet(configured)
    by_name = db.session.query(Slip).filter(Slip.name == WALLET_ADMIN_SLIP_NAME).one_or_none()
    print("   found by WALLET :", by_wallet.name if by_wallet else "(none)")
    print("   found by NAME   :", by_name.name if by_name else "(none)")

    slip = by_wallet or by_name
    if slip is None:
        problems.append(
            "No admin slip exists at all. /admin/login would try to create one, "
            "and that create is the write that is failing."
        )
    else:
        print("   id=%s is_admin=%s auth_mode=%s" % (
            slip.id, slip.is_admin, slip_auth_mode(slip)))
        if not slip.is_admin:
            problems.append("The admin slip does not have is_admin set.")
            fixes.append(("set is_admin on slip %s" % slip.id,
                          lambda s=slip: setattr(s, "is_admin", True)))
        if slip_auth_mode(slip) == AUTH_MODE_PASSWORD:
            problems.append(
                "The admin slip is PASSWORD-ONLY, and its password is a random "
                "hash nobody knows — so it cannot be signed into by any means."
            )
            fixes.append(("widen auth_mode to 'either' on slip %s" % slip.id,
                          lambda s=slip: setattr(s, "auth_mode", AUTH_MODE_EITHER)))

    _hr("3. The wallet link (this is what the SITE login needs)")
    if slip is not None:
        profile = db.session.query(Profile).filter(Profile.slip_id == slip.id).one_or_none()
        if profile is None:
            print("   no Profile row for this slip")
            holder = slip_for_wallet(configured)
            if holder is not None and holder.id != slip.id:
                problems.append(
                    "%s is already linked to slip %s (%s). Free it or point "
                    "ADMIN_WALLET_ADDRESS elsewhere." % (configured, holder.id, holder.name))
            else:
                problems.append(
                    "The admin wallet is not linked to any slip, so the site's "
                    "'Sign in with MetaMask' cannot find it.")
                # slug is NOT NULL and UNIQUE; omitting it raises
                # NotNullViolation. Convention from blueprints/profiles.py.
                fixes.append(("create Profile(slip_id=%s, slug=user-%s, eth_address=%s)"
                              % (slip.id, slip.id, configured),
                              lambda s=slip: db.session.add(Profile(
                                  slip_id=s.id, slug="user-%s" % s.id,
                                  eth_address=configured))))
        else:
            linked = normalize_wallet_address(profile.eth_address)
            print("   Profile.eth_address =", linked or "(empty)")
            if not linked:
                problems.append("The admin slip's profile has no wallet address.")
                fixes.append(("set eth_address=%s on profile %s" % (configured, profile.id),
                              lambda p=profile: setattr(p, "eth_address", configured)))
            elif linked != configured:
                problems.append(
                    "The admin slip is linked to %s but the configured wallet is "
                    "%s. Not changing it automatically." % (linked, configured))

    _hr("4. Can the write that /admin/login performs actually succeed?")
    # This is the step the error message is about. Attempted inside a savepoint
    # so a failure here changes nothing.
    try:
        with db.session.begin_nested():
            from model.Slip import ensure_wallet_admin_slip
            made = ensure_wallet_admin_slip()
            db.session.flush()
            print("   ensure_wallet_admin_slip() OK -> slip id=%s" % made.id)
        db.session.rollback()
    except Exception as error:
        db.session.rollback()
        print("   ensure_wallet_admin_slip() FAILED")
        print("   %s: %s" % (type(error).__name__, error))
        print()
        traceback.print_exc()
        problems.append(
            "ensure_wallet_admin_slip() raises: %s: %s — this is the cause of "
            "'Session creation failed'." % (type(error).__name__, error))

    _hr("Summary")
    if not problems:
        print("   No problems found. If /admin/login still fails, the cause is")
        print("   outside this script — capture the exception from step 4.")
    for i, p in enumerate(problems, 1):
        print("   %d. %s" % (i, p))

    if fixes:
        print("\n   Repairs available:")
        for label, _ in fixes:
            print("     -", label)
        if repair:
            for label, apply in fixes:
                print("   applying:", label)
                apply()
            db.session.commit()
            print("\n   Committed. Try /admin/login again.")
        else:
            print("\n   Re-run with --repair to apply them.")
    return 1 if problems else 0


if __name__ == "__main__":
    with app.app_context():
        sys.exit(diagnose(repair="--repair" in sys.argv))
