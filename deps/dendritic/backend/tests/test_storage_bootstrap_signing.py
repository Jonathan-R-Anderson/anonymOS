"""The bootstrap document, and why it has to be signed before gateways serve it.

This document decides two things for a joining node: which peers it dials, and
which coordinator key it accepts for storage leases. A node that reads the key
OUT of the document is trusting whoever served the document — survivable while
exactly one host under our own TLS serves it, and not survivable the moment the
job is spread across volunteer gateways, which is the point of doing so.
"""

import ast
import base64
import os
import pathlib
import sys
import unittest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

try:
    from nacl.signing import SigningKey, VerifyKey
    HAVE_NACL = True
except Exception:
    HAVE_NACL = False


def _load_pure(relative_path, wanted, extra=None):
    source = (pathlib.Path(BACKEND) / relative_path).read_text()
    tree = ast.parse(source)
    keep = [node for node in tree.body
            if (isinstance(node, ast.Assign)
                and {t.id for t in node.targets if isinstance(t, ast.Name)} & wanted)
            or (isinstance(node, (ast.FunctionDef, ast.ClassDef))
                and node.name in wanted)]
    module = ast.Module(body=keep, type_ignores=[])
    ast.fix_missing_locations(module)
    namespace = dict(extra or {})
    exec(compile(module, relative_path, "exec"), namespace)
    return namespace


SC = _load_pure("services/storage_coordination.py", {"bootstrap_message"})

PEERS = [
    "/garlic32/aaaa/p2p/12D3KooWA",
    "/garlic32/bbbb/p2p/12D3KooWB",
    "/garlic32/cccc/p2p/12D3KooWC",
]
KEY = "lKlnLi9ti07xbL/fKKizbgcxFMpUZqWavQdv3NuBmw4"
EXPIRES = "2026-08-01T21:57:28.877772Z"


def message(peers=PEERS, key=KEY, expires=EXPIRES):
    return SC["bootstrap_message"](peers, key, expires)


class MessageTest(unittest.TestCase):
    def test_every_decision_the_document_makes_is_covered(self):
        """A field outside the signed message can be altered in flight without
        invalidating anything — and each of these decides who a node talks to
        or what it trusts."""
        text = message().decode()
        self.assertIn(KEY, text)
        self.assertIn(EXPIRES, text)
        for peer in PEERS:
            self.assertIn(peer, text)

    def test_the_peer_count_is_signed_before_the_peers(self):
        """Dropping peers is how a node is steered toward the few somebody
        controls. A signed count means a truncated list cannot pass as
        complete."""
        text = message().decode()
        self.assertIn("peers: 3", text)
        self.assertLess(text.index("peers: 3"), text.index(PEERS[0]))

    def test_removing_a_peer_changes_the_message(self):
        self.assertNotEqual(message(), message(peers=PEERS[:2]))

    def test_reordering_peers_changes_the_message(self):
        """Order is meaningful: live peers come before the static seed, so a
        reorder decides which a joining node dials first."""
        self.assertNotEqual(message(), message(peers=list(reversed(PEERS))))

    def test_swapping_the_coordinator_key_changes_the_message(self):
        """The whole reason this is signed."""
        self.assertNotEqual(message(), message(key="AAAA" + KEY[4:]))

    def test_extending_the_expiry_changes_the_message(self):
        """Otherwise a captured document is replayable forever."""
        self.assertNotEqual(message(), message(expires="2099-01-01T00:00:00Z"))

    def test_it_starts_with_a_version_marker(self):
        self.assertTrue(message().decode().startswith(
            "syndichan-storage-bootstrap-v1"))

    def test_an_empty_peer_list_still_signs(self):
        """A young network legitimately has no peers to offer; the document
        must still be verifiable rather than unsigned."""
        self.assertIn("peers: 0", message(peers=[]).decode())


@unittest.skipUnless(HAVE_NACL, "PyNaCl is not installed here")
class SignatureTest(unittest.TestCase):
    def test_a_signature_over_it_verifies(self):
        key = SigningKey.generate()
        public = base64.b64encode(
            key.verify_key.encode()).decode("ascii").rstrip("=")
        signature = key.sign(message(key=public)).signature
        VerifyKey(key.verify_key.encode()).verify(message(key=public), signature)

    def test_another_key_does_not_verify(self):
        key, other = SigningKey.generate(), SigningKey.generate()
        blob = message()
        signature = key.sign(blob).signature
        with self.assertRaises(Exception):
            VerifyKey(other.verify_key.encode()).verify(blob, signature)

    def test_a_forged_peer_list_does_not_verify(self):
        """The attack this closes: a gateway serving the document swaps the
        peers for ones it controls, and the node dials those instead."""
        key = SigningKey.generate()
        signature = key.sign(message()).signature
        forged = message(peers=["/garlic32/evil/p2p/12D3KooWEvil"])
        with self.assertRaises(Exception):
            VerifyKey(key.verify_key.encode()).verify(forged, signature)


if __name__ == "__main__":
    unittest.main()
