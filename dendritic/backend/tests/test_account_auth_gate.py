"""When changing your own username/password needs a current password first.

THE BUG THIS EXISTS FOR
-----------------------
The wallet admin was created with `generate_password_hash(secrets.token_hex(32))`
— a random string that was hashed and thrown away. No password for that account
has ever existed, so "enter your current password" is a demand for a string
nobody can produce.

The first version of this gate exempted `auth_mode == "wallet"`, which sounded
right and did nothing: the wallet admin's mode is "either", so it was still
asked. The account the feature was written for was the one account it did not
work for.

So the gate keys on how THIS SESSION was proved, not on the slip's mode. An
"either" slip may hold a real password or a random one and the mode cannot tell
them apart — but a session that arrived by signature has already proved
ownership either way.
"""

import ast
import os
import pathlib
import sys
import unittest

BACKEND = pathlib.Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))


class _FakeSession(dict):
    pass


def _load_gate(session_data, admin_wallet=None, cookie_wallet=None):
    """Exec just the auth-mode helpers with a fake flask session."""
    source = (BACKEND / "model" / "Slip.py").read_text()
    tree = ast.parse(source)
    wanted = {"AUTH_MODE_PASSWORD", "AUTH_MODE_WALLET", "AUTH_MODE_EITHER",
              "AUTH_MODES", "DEFAULT_AUTH_MODE", "ADMIN_WALLET_SESSION_KEY",
              "SESSION_AUTH_KEY", "AUTH_BY_PASSWORD", "AUTH_BY_WALLET",
              "normalize_wallet_address", "is_wallet_admin_session",
              "session_proved_by_wallet", "slip_auth_mode",
              "slip_allows_password_login"}
    keep = [node for node in tree.body
            if (isinstance(node, ast.Assign)
                and {t.id for t in node.targets if isinstance(t, ast.Name)} & wanted)
            or (isinstance(node, (ast.FunctionDef, ast.ClassDef))
                and node.name in wanted)]
    module = ast.Module(body=keep, type_ignores=[])
    ast.fix_missing_locations(module)
    namespace = {
        "session": _FakeSession(session_data),
        "configured_admin_wallet_address": lambda: admin_wallet,
    }
    exec(compile(module, "model/Slip.py", "exec"), namespace)
    return namespace


class _Slip:
    def __init__(self, auth_mode):
        self.auth_mode = auth_mode


def _needs_password(gate, slip):
    """The rule as blueprints/profiles.py applies it."""
    return (gate["slip_allows_password_login"](slip)
            and not gate["session_proved_by_wallet"]())


class GateTest(unittest.TestCase):
    ADMIN = "0xabc0000000000000000000000000000000000001"

    def test_the_wallet_admin_is_not_asked_for_a_password_it_never_had(self):
        # THE regression. auth_mode is "either", not "wallet" — testing the mode
        # instead of the session is what broke this.
        gate = _load_gate({"admin-wallet-address": self.ADMIN},
                          admin_wallet=self.ADMIN)
        self.assertFalse(_needs_password(gate, _Slip("either")))

    def test_a_signature_proved_session_is_exempt_whatever_the_mode(self):
        for mode in ("either", "password", "wallet"):
            gate = _load_gate({"auth-method": "wallet"}, admin_wallet=self.ADMIN)
            self.assertFalse(_needs_password(gate, _Slip(mode)), mode)

    def test_a_password_session_must_still_supply_one(self):
        # The protection this gate exists for: a borrowed session that can
        # rename an account can impersonate its owner on every post they made.
        gate = _load_gate({"auth-method": "password"}, admin_wallet=self.ADMIN)
        self.assertTrue(_needs_password(gate, _Slip("either")))
        self.assertTrue(_needs_password(gate, _Slip("password")))

    def test_an_unmarked_session_is_treated_as_a_password_session(self):
        # Sessions created before the marker existed carry nothing. Defaulting
        # the OTHER way would drop the check for every session on the site.
        gate = _load_gate({}, admin_wallet=self.ADMIN)
        self.assertTrue(_needs_password(gate, _Slip("either")))
        self.assertTrue(_needs_password(gate, _Slip("password")))

    def test_a_wallet_only_slip_is_exempt_with_no_marker_at_all(self):
        # It has no password by construction, so there is nothing to ask for.
        gate = _load_gate({}, admin_wallet=self.ADMIN)
        self.assertFalse(_needs_password(gate, _Slip("wallet")))

    def test_somebody_elses_wallet_in_the_cookie_is_not_the_admin(self):
        gate = _load_gate({"admin-wallet-address": "0xdead"}, admin_wallet=self.ADMIN)
        self.assertTrue(_needs_password(gate, _Slip("either")))

    def test_no_configured_admin_wallet_does_not_make_everybody_one(self):
        # `None == None` would otherwise be true, and this same helper grants
        # moderation elsewhere — so an install with no admin wallet configured
        # would hand every anonymous visitor the admin's session.
        gate = _load_gate({}, admin_wallet=None)
        self.assertFalse(gate["is_wallet_admin_session"]())
        self.assertTrue(_needs_password(gate, _Slip("either")))

    def test_the_admin_marker_is_compared_case_insensitively(self):
        # Wallets are handed around checksummed; a case-sensitive compare would
        # silently fail to recognise the admin's own session.
        gate = _load_gate({"admin-wallet-address": self.ADMIN.upper()},
                          admin_wallet=self.ADMIN)
        self.assertFalse(_needs_password(gate, _Slip("either")))


if __name__ == "__main__":
    unittest.main()
