import ast
import os
from pathlib import Path
import unittest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

from services.client_ip import resolve_client_ip


_BACKEND = Path(__file__).resolve().parents[1]


def _function_calls(relative_path, function_name):
    tree = ast.parse((_BACKEND / relative_path).read_text(encoding="utf-8"))
    function = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == function_name
    )
    return {
        node.func.id
        for node in ast.walk(function)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }


# These tests read files removed with the stripped features: blueprints/bot_api.py.
#
# SKIPPED CONDITIONALLY RATHER THAN DELETED, matching the civil-rights
# classes in test_evidence_upload.py. The assertions are still correct and
# worth keeping; a skipUnless brings them back the moment the files exist
# again, which a deletion cannot do. PER METHOD, not per class: these
# classes are MIXED, and skipping a whole one destroys its working tests.
_BOT_API_PRESENT = all(
    os.path.exists(os.path.join(BACKEND, part)) for part in (
        "blueprints/bot_api.py",
    )
)
_BOT_API_PRESENT_GONE = "the bot-api blueprint was removed; this reads it"

class ClientIpTest(unittest.TestCase):
    def test_direct_address_ignores_forged_forwarded_header(self):
        self.assertEqual(
            "198.51.100.9",
            resolve_client_ip("198.51.100.9", "203.0.113.44", ()),
        )

    def test_trusted_proxy_yields_client(self):
        self.assertEqual(
            "203.0.113.44",
            resolve_client_ip(
                "172.20.0.8",
                "203.0.113.44",
                ("172.16.0.0/12",),
            ),
        )

    def test_trusted_proxy_chain_is_walked_right_to_left(self):
        self.assertEqual(
            "2001:db8::55",
            resolve_client_ip(
                "172.20.0.8",
                "2001:db8::55, 172.21.0.4",
                ("172.16.0.0/12",),
            ),
        )

    def test_malformed_forwarded_chain_falls_back_to_peer(self):
        self.assertEqual(
            "172.20.0.8",
            resolve_client_ip(
                "172.20.0.8",
                "203.0.113.44, not-an-ip",
                ("172.16.0.0/12",),
            ),
        )

    def test_untrusted_intermediate_proxy_is_the_observed_client(self):
        self.assertEqual(
            "192.0.2.20",
            resolve_client_ip(
                "172.20.0.8",
                "203.0.113.44, 192.0.2.20",
                ("172.16.0.0/12",),
            ),
        )

    def test_ip_ban_enforcement_uses_central_trust_boundary(self):
        self.assertIn(
            "get_client_ip",
            _function_calls("app.py", "_redirect_banned_visitors"),
        )
        banned = {"203.0.113.44"}
        observed = resolve_client_ip(
            "10.42.0.8", "203.0.113.44", ("10.42.0.0/16",)
        )
        self.assertIn(observed, banned)

    def test_country_flag_posting_uses_central_trust_boundary(self):
        self.assertIn(
            "get_client_ip",
            _function_calls("post.py", "get_ip_address"),
        )
        self.assertIn(
            "country_for_ip",
            _function_calls("post.py", "_resolve_country"),
        )
        observed = resolve_client_ip(
            "10.42.0.8", "203.0.113.44", ("10.42.0.0/16",)
        )
        self.assertEqual("203.0.113.44", observed)

    def test_live_visitor_map_uses_central_trust_boundary(self):
        self.assertIn(
            "get_ip_address",
            _function_calls("blueprints/main.py", "presence_ping"),
        )
        self.assertIn(
            "record_presence",
            _function_calls("blueprints/main.py", "presence_ping"),
        )
        first = resolve_client_ip(
            "10.42.0.8", "203.0.113.44", ("10.42.0.0/16",)
        )
        second = resolve_client_ip(
            "10.42.0.8", "198.51.100.9", ("10.42.0.0/16",)
        )
        self.assertEqual(2, len({first, second}))

    @unittest.skipUnless(_BOT_API_PRESENT, _BOT_API_PRESENT_GONE)
    def test_bot_token_ip_lock_uses_central_trust_boundary(self):
        self.assertIn(
            "get_client_ip",
            _function_calls("blueprints/bot_api.py", "_client_ip"),
        )
        registered = "203.0.113.44"
        observed = resolve_client_ip(
            "10.42.0.8", registered, ("10.42.0.0/16",)
        )
        self.assertEqual(registered, observed)
        forged = resolve_client_ip(
            "198.51.100.9", registered, ("10.42.0.0/16",)
        )
        self.assertNotEqual(registered, forged)


if __name__ == "__main__":
    unittest.main()
