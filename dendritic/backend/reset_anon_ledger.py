"""Wipe the AXON ledger so a fresh contract deployment starts from zero.

WHY THIS EXISTS
---------------
The contract stack moved from Ethereum mainnet to Ethereum mainnet, which means new
contracts at new addresses. Everything the old deployment recorded — credit
purchases, the receipts nodes earned, the epochs those receipts sat in — refers
to a token that will not exist on the new chain. None of it can ever pay out,
and leaving it in place is worse than useless: the first mainnet epoch would try
to settle thousands of receipts against contracts that never saw them.

WHAT IT DELETES
---------------
  credit_grant     manual AXONCoin transfers, sent on the old chain or never sent
  credit_purchase  store/Stripe purchase records
  pof_receipt      signed node-work receipts awaiting settlement
  pof_settlement   per-epoch settlement rows (roots, claims, submitted tx)
  site_setting     the saved contract addresses, which point at the old chain

WHAT IT RESETS RATHER THAN DELETES
----------------------------------
  signup_grant
      The 20-AXON-per-account grants. Deleting these would be a sybil hole:
      the table's own uniqueness constraints (one per slip, one per wallet) and
      its network-hash indexes are what stop the same person claiming twice, and
      a wiped table remembers nobody. But a grant marked "claimed" points at a
      CreditGrant that is about to be deleted, and describes AXON delivered on a
      chain that no longer matters — so leaving it claimed would quietly cheat
      everyone who signed up early out of the tokens they were promised.

      So claimed rows go back to pending with credit_grant_id cleared. The
      person keeps their place in the anti-sybil ledger and gets paid on the
      chain that counts. (This also has to happen BEFORE credit_grant is
      deleted, since that FK has no ON DELETE clause and would otherwise refuse
      the delete outright.)

WHAT IT KEEPS, DELIBERATELY
---------------------------
  pof_registration / pof_payout
      Node identities and the wallets they are paid to. These are not
      transactions — they are who is on the network. Deleting them would make
      every operator re-register a node that never stopped running.

  pof_assignment
      What each node advertises it currently holds. This is live state
      describing data that is on disk right now, not a record of past work.
      Deleting it would tell the challenger that nobody is storing anything.

  Wallet balances
      Not ours to touch. AXON lives in the holder's wallet on chain; this
      database has never been the authority on a balance and cannot change one.

USAGE
-----
    python reset_anon_ledger.py              # census only, changes nothing
    python reset_anon_ledger.py --yes        # actually do it

Dry run is the default on purpose. A destructive one-shot that runs on invocation
is one stray shell-history arrow-up away from being run twice.
"""

import argparse
import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from shared import app, db  # noqa: E402


# (table, why it goes) in a delete order that respects foreign keys:
# credit_grant references credit_purchase, so the child is listed first.
TARGETS = [
    ("credit_grant", "manual AXONCoin transfers"),
    ("credit_purchase", "store/Stripe purchase records"),
    ("pof_receipt", "node-work receipts held for settlement"),
    ("pof_settlement", "per-epoch settlement rows"),
]

CONTRACTS_SETTING = "pof_contracts"


def _count(table, where=None):
    """Row count, or None if the table cannot be read.

    Raw SQL rather than the models, and tolerant of a missing table: an older
    database or a partial migration can be short one of these, and a census that
    dies on the first absent table tells you nothing about the rest.
    """
    from sqlalchemy import text

    sql = "SELECT COUNT(*) FROM %s" % table
    if where:
        sql += " WHERE " + where
    try:
        return int(db.session.execute(text(sql)).scalar() or 0)
    except Exception:
        db.session.rollback()
        return None


def saved_contracts():
    import json

    from model.SiteSetting import get_setting

    raw = get_setting(CONTRACTS_SETTING)
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--yes", action="store_true",
                    help="actually make the changes (default is a dry-run census)")
    ap.add_argument("--keep-addresses", action="store_true",
                    help="leave the saved contract addresses alone")
    args = ap.parse_args()

    with app.app_context():
        from sqlalchemy import text

        counts = [(table, _count(table), why) for table, why in TARGETS]
        claimed = _count("signup_grant", "status = 'claimed'")
        addresses = saved_contracts()

        print("AXON ledger census")
        print("-" * 62)
        total = 0
        for table, n, why in counts:
            if n is None:
                print("  %-18s  %8s  %s (table unreadable)" % (table, "-", why))
                continue
            total += n
            print("  %-18s  %8d  %s" % (table, n, why))
        print("  %-18s  %8d  to delete" % ("TOTAL", total))
        print("  %-18s  %8s  reset to pending, not deleted"
              % ("signup_grant", "-" if claimed is None else claimed))

        if addresses:
            print("\nSaved contract addresses (point at the OLD chain):")
            for name in sorted(addresses):
                print("  %-22s %s" % (name, addresses[name]))
        else:
            print("\nNo contract addresses saved.")

        clearing_addresses = bool(addresses) and not args.keep_addresses
        if not args.yes:
            print("\nDry run — nothing was changed. Re-run with --yes to do it.")
            return 0
        if not total and not claimed and not clearing_addresses:
            print("\nNothing to do.")
            return 0

        print("\nApplying…")

        # First, because credit_grant.id is referenced here and that FK has no
        # ON DELETE clause — the delete below fails while these rows point at it.
        if claimed:
            db.session.execute(text(
                "UPDATE signup_grant SET status = 'pending', credit_grant_id = NULL, "
                "claimed_at = NULL WHERE status = 'claimed'"))
            print("  %-18s  %8d reset to pending" % ("signup_grant", claimed))
        else:
            # Nothing claimed, but a pending row can still hold a stale link.
            db.session.execute(text(
                "UPDATE signup_grant SET credit_grant_id = NULL "
                "WHERE credit_grant_id IS NOT NULL"))

        deleted = 0
        for table, n, _why in counts:
            if not n:
                continue
            # DELETE, not TRUNCATE: truncate needs table-owner rights the app
            # role may not have, and takes a lock that would stall live requests.
            db.session.execute(text("DELETE FROM %s" % table))
            deleted += n
            print("  %-18s  %8d removed" % (table, n))

        if clearing_addresses:
            from model.SiteSetting import set_setting

            set_setting(CONTRACTS_SETTING, "{}")
            print("  %-18s  %8d cleared" % ("contract addresses", len(addresses)))

        db.session.commit()
        print("\nDone. %d row(s) removed. The ledger is empty and ready for the "
              "new deployment." % deleted)
        return 0


if __name__ == "__main__":
    sys.exit(main())
