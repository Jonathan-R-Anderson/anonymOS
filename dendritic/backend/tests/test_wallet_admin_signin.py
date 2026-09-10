"""The admin wallet must be able to sign in — on BOTH sign-in paths.

THE BUG THIS EXISTS FOR
-----------------------
The operator reported "I cannot log into the site using my MetaMask account".
Probing the live site ruled out the two obvious causes: the signature verifier
was reachable (a bad signature returned 403 "Invalid wallet signature", not a
502), and the pinned address matched the wallet being used.

Reading `ensure_wallet_admin_slip` found two faults stacked, and each one alone
is enough to lock the admin out of the site sign-in:

  1. THE WALLET WAS NEVER LINKED. The address was attached to a Profile only in
     the legacy branch — the one reached when a slip named "wallet-admin"
     ALREADY existed. On a fresh install the slip was created with no Profile
     and no eth_address, so `slip_for_wallet()` could never find it and the
     site's "Sign in with MetaMask" answered "No slip is linked to 0x…" for the
     admin's own wallet, permanently.

  2. THE SLIP WAS PASSWORD-ONLY. `DEFAULT_AUTH_MODE` is password, and
     `slip_allows_wallet_login()` requires wallet or either. The slip's password
     is `generate_password_hash(secrets.token_hex(32))` — hashed and discarded,
     knowable by nobody. So the account could not be signed into by ANY means:
     the password is unknowable and the wallet was refused.

What made it hard to see is that the two sign-in paths DISAGREED. `/admin/login`
worked, because `begin_wallet_admin_session` calls `ensure_wallet_admin_slip`
and needs neither the link nor the auth mode. The site login did not. An
operator using the front page saw a flat refusal while the admin dashboard let
them in, which reads like a permissions problem rather than a missing row.

These tests read the SOURCE rather than standing up a database, matching
test_account_auth_gate.py: the properties are about what the function does to a
newly created slip, and they must hold without a live app context.
"""

import ast
import os
import pathlib
import sys
import unittest

BACKEND = pathlib.Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

SLIP_SRC = (BACKEND / "model" / "Slip.py").read_text()
SLIP_TREE = ast.parse(SLIP_SRC)


def _func(name, tree=None):
    for node in ast.walk(tree or SLIP_TREE):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError("%s not found" % name)


def _src(node):
    return ast.get_source_segment(SLIP_SRC, node) or ""


class WalletAdminSlipIsLinked(unittest.TestCase):
    def test_creation_path_links_the_configured_wallet(self):
        """Fault 1. The newly-created slip must get the wallet attached.

        Asserted on the CALL rather than on a Profile literal, because the
        linking moved into a helper — the property is that the creation path
        reaches it, however it is spelled.
        """
        src = _src(_func("ensure_wallet_admin_slip"))
        self.assertIn(
            "_link_wallet_to_slip", src,
            "ensure_wallet_admin_slip no longer links the wallet; a fresh install "
            "will create an admin slip that slip_for_wallet() can never find, and "
            "the site's MetaMask sign-in will refuse the admin's own wallet",
        )
        # And it must be reached on the fall-through, not only inside the
        # early-return branch that handles an already-linked slip.
        tail = src[src.index("slip = db.session.query(Slip)"):]
        self.assertIn(
            "_link_wallet_to_slip", tail,
            "the wallet is linked only before the slip is created/found; the "
            "creation path is exactly the one that was broken",
        )

    def test_linking_never_steals_an_address_from_another_slip(self):
        """Profile.eth_address is UNIQUE.

        Assigning an address another slip holds raises on flush, and the caller
        that would take the exception is the admin login path. A conflict has to
        be refused and logged, not attempted.
        """
        src = _src(_func("_link_wallet_to_slip"))
        self.assertIn("slip_for_wallet(address)", src,
                      "no check for an existing holder before assigning a UNIQUE column")
        self.assertIn("return False", src, "a conflict must be refused, not raised")
        self.assertIn("app.logger.error", src,
                      "a refused link must be logged; silence here is an admin who "
                      "cannot sign in and no reason why")

    def test_existing_link_is_not_overwritten(self):
        """Overwriting would silently move the admin identity to another wallet."""
        # Searched across BOTH functions, because the write moved into a helper
        # when the savepoint went in and a name-scoped assertion would have
        # passed vacuously the moment it moved again.
        src = _src(_func("_link_wallet_to_slip")) + _src(_func("_write_wallet_link"))
        self.assertIn("not overwriting", src,
                      "a slip already pointing at a different wallet must be left alone")


class WalletAdminSlipCanActuallySignIn(unittest.TestCase):
    def test_created_slip_is_not_password_only(self):
        """Fault 2. A password-only slip whose password is unknowable is a dead account."""
        src = _src(_func("ensure_wallet_admin_slip"))
        create = src[src.index("slip = Slip("):]
        self.assertIn(
            "auth_mode=AUTH_MODE_EITHER", create,
            "the wallet-admin slip is created on the default auth mode. Its password "
            "is a random hex string that is hashed and discarded, so password login "
            "is impossible; if the wallet is also refused, NOTHING can sign in",
        )

    def test_default_auth_mode_is_still_password_for_everyone_else(self):
        """The fix must be scoped to this one slip.

        If DEFAULT_AUTH_MODE itself were widened, every account in the system
        would silently accept wallet sign-in — which is a much larger change
        than the one this bug needs, and not one anybody asked for.
        """
        for node in ast.walk(SLIP_TREE):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "DEFAULT_AUTH_MODE":
                        self.assertEqual(
                            getattr(node.value, "id", None), "AUTH_MODE_PASSWORD",
                            "DEFAULT_AUTH_MODE was widened; that changes sign-in for "
                            "every account, not just the admin",
                        )
                        return
        self.fail("DEFAULT_AUTH_MODE not found")

    def test_existing_password_only_admin_is_repaired(self):
        """An install created before the fix must be repaired on the next call.

        Without this, the fix only helps installs that have not run yet — and the
        one that reported the bug is not one of those.
        """
        src = _src(_func("ensure_wallet_admin_slip"))
        self.assertIn("slip_auth_mode(slip) == AUTH_MODE_PASSWORD", src,
                      "an already-created password-only admin slip is never widened, "
                      "so the running install stays locked out")
        self.assertIn("AUTH_MODE_EITHER", src)

    def test_repair_widens_rather_than_forces_wallet_only(self):
        """An operator who set a real password on this slip keeps it working."""
        src = _src(_func("ensure_wallet_admin_slip"))
        repair = src[src.index("slip_auth_mode(slip) == AUTH_MODE_PASSWORD"):]
        self.assertNotIn("AUTH_MODE_WALLET", repair.split("db.session.flush()")[0],
                         "repair forces wallet-only, which would break a slip that "
                         "has since been given a real password")


class BothSignInPathsAgree(unittest.TestCase):
    def test_admin_login_and_site_login_use_the_same_identity(self):
        """The divergence is what made this hard to diagnose.

        `/admin/login` resolves the slip through ensure_wallet_admin_slip, which
        creates what it needs. The site login resolves it through
        slip_for_wallet, which only reads. So one path could succeed while the
        other failed for the same wallet, and did.
        """
        begin = _src(_func("begin_wallet_admin_session"))
        self.assertIn("ensure_wallet_admin_slip()", begin)
        # ensure_wallet_admin_slip must now leave behind exactly what
        # slip_for_wallet needs, so that a successful /admin/login also repairs
        # the site path.
        ensure = _src(_func("ensure_wallet_admin_slip"))
        self.assertIn("_link_wallet_to_slip", ensure,
                      "signing in at /admin/login must leave the wallet linked, or the "
                      "site login stays broken for someone who just proved ownership")


if __name__ == "__main__":
    unittest.main()


class AdminLoginDegradesRatherThanRefuses(unittest.TestCase):
    """The operator reported "Session creation failed; check server logs".

    That message means the signature verified and the address matched — the
    failure was in creating the session, i.e. in a WRITE. Everything this class
    checks exists because of one property:

        admin sign-in is the recovery path for a hosted deployment. The logs are
        behind the dashboard the operator cannot reach, so a lockout here is a
        lockout with no visible cause. Nothing optional may stand between a
        proved signature and a session.
    """

    def test_wallet_link_failure_cannot_fail_the_transaction(self):
        src = _src(_func("_link_wallet_to_slip"))
        self.assertIn("begin_nested", src,
                      "the wallet link is not savepointed, so a UNIQUE collision or a "
                      "column an un-run migration never created poisons the whole "
                      "transaction — and the caller is the admin login path")
        self.assertIn("except SQLAlchemyError", src)

    def test_auth_mode_repair_cannot_fail_the_transaction(self):
        src = _src(_func("ensure_wallet_admin_slip"))
        repair = src[src.index("slip_auth_mode(slip) == AUTH_MODE_PASSWORD"):]
        self.assertIn("begin_nested", repair,
                      "widening auth_mode is a repair, not a precondition; if the column "
                      "is missing the admin must still get in to fix it")

    def test_session_creation_falls_back_to_a_read_only_lookup(self):
        src = _src(_func("begin_wallet_admin_session"))
        self.assertIn("except SQLAlchemyError", src,
                      "ensure_wallet_admin_slip creates and repairs; if any of that fails "
                      "an EXISTING admin slip is still fine to sign in as")
        self.assertIn("WALLET_ADMIN_SLIP_NAME", src,
                      "no read-only fallback lookup")
        self.assertIn("db.session.rollback()", src,
                      "a failed flush leaves the session unusable; the fallback query would "
                      "raise too without a rollback first")

    def test_the_fallback_does_not_invent_a_session(self):
        """If there is genuinely nothing to sign in as, say so.

        A fallback that quietly produced an empty session would turn a visible
        failure into an admin session belonging to nobody, which is worse than
        the lockout it was meant to fix.
        """
        src = _src(_func("begin_wallet_admin_session"))
        tail = src[src.index("if slip is None:"):]
        self.assertIn("raise", tail,
                      "the fallback must re-raise when no admin slip exists")

    def test_the_error_reaches_the_operator(self):
        """"check server logs" is useless advice to someone who cannot reach them."""
        admin = (BACKEND / "blueprints" / "admin.py").read_text()
        start = admin.index("def wallet_verify")
        block = admin[start:start + 4000]
        self.assertIn("type(error).__name__", block,
                      "the session-creation failure still returns a generic message; the "
                      "operator has no way to see the cause")
        # Normalised: the justification is a wrapped comment, so a literal
        # substring search would break on a reflow rather than on a removal.
        flat = " ".join(block.replace("#", " ").split())
        self.assertIn("proved by signature", flat,
                      "the reason this disclosure is safe must be written down, or a "
                      "later reviewer will correctly remove it")
