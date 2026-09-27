"""Origin signatures, and the attacks they are supposed to stop.

Every test here is a gateway trying something. The point of the mechanism is
that a gateway is untrusted transport, so the tests are written from its side
rather than from the happy path.
"""

import base64
import hashlib
import os
import sys
import unittest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from nacl.signing import SigningKey  # noqa: E402


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


def sha256_hex(data):
    return hashlib.sha256(data if isinstance(data, bytes) else data.encode()).hexdigest()


OBJECT_PREFIX = b"syndichan-object:v1"


def object_message(key, version, body_hash):
    """Mirrors services.content_signing.object_message.

    Restated rather than imported because that module pulls in the Flask app.
    This is the wire format a client reimplements, and if the two ever disagree
    the signatures stop verifying — which is exactly what this file is for.
    """
    return b"\n".join([OBJECT_PREFIX, str(key).encode(),
                       str(int(version)).encode(), str(body_hash).encode()])


def merkle_root(leaves):
    if not leaves:
        return sha256_hex(b"")
    level = [bytes.fromhex(h) for h in leaves]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest()
                 for i in range(0, len(level), 2)]
    return level[0].hex()


def merkle_proof(leaves, index):
    level = [bytes.fromhex(h) for h in leaves]
    path, position = [], index
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        pair = position ^ 1
        path.append({"hash": level[pair].hex(),
                     "side": "right" if pair > position else "left"})
        level = [hashlib.sha256(level[i] + level[i + 1]).digest()
                 for i in range(0, len(level), 2)]
        position //= 2
    return path


def verify_merkle(leaf, path, root):
    current = bytes.fromhex(leaf)
    for step in path:
        sibling = bytes.fromhex(step["hash"])
        current = (hashlib.sha256(sibling + current).digest() if step["side"] == "left"
                   else hashlib.sha256(current + sibling).digest())
    return current.hex() == root


class ObjectSignatureTest(unittest.TestCase):
    def setUp(self):
        self.key = SigningKey.generate()
        self.pub = self.key.verify_key

    def sign(self, key, version, body):
        return self.key.sign(object_message(key, version, sha256_hex(body))).signature

    def verify(self, key, version, body, signature):
        from nacl.exceptions import BadSignatureError
        try:
            self.pub.verify(object_message(key, version, sha256_hex(body)), signature)
            return True
        except BadSignatureError:
            return False

    def test_untouched_content_verifies(self):
        body = b"<html>thread 123</html>"
        self.assertTrue(self.verify("/thread/123", 7, body, self.sign("/thread/123", 7, body)))

    def test_one_flipped_byte_is_caught(self):
        # The whole promise: a gateway cannot change a single byte undetected.
        body = b"<html>thread 123</html>"
        signature = self.sign("/thread/123", 7, body)
        self.assertFalse(self.verify("/thread/123", 7, b"<html>thread 124</html>", signature))

    def test_injected_script_is_caught(self):
        body = b"<html>hello</html>"
        signature = self.sign("/thread/1", 1, body)
        tampered = b"<html>hello<script>steal()</script></html>"
        self.assertFalse(self.verify("/thread/1", 1, tampered, signature))

    def test_a_signature_cannot_be_moved_to_another_object(self):
        # A gateway serving /thread/9 must not be able to present the signature
        # it legitimately holds for /thread/1, which is why the key is signed.
        body = b"same bytes"
        signature = self.sign("/thread/1", 3, body)
        self.assertFalse(self.verify("/thread/9", 3, body, signature))

    def test_a_signature_cannot_be_moved_to_another_version(self):
        body = b"same bytes"
        signature = self.sign("/thread/1", 3, body)
        self.assertFalse(self.verify("/thread/1", 4, body, signature))

    def test_a_stale_copy_stays_authentic_which_is_why_version_matters(self):
        # This one PASSES verification and must: version 6 really was signed.
        # It is recorded here because it is the reason clients have to track the
        # highest version they have seen — the signature alone cannot tell a
        # reader they are being served last week's thread.
        old = b"<html>two replies</html>"
        old_signature = self.sign("/thread/1", 6, old)
        self.assertTrue(self.verify("/thread/1", 6, old, old_signature))

    def test_another_key_cannot_sign(self):
        # A gateway with its own keypair — the Sybil case.
        rogue = SigningKey.generate()
        body = b"<html>hi</html>"
        forged = rogue.sign(object_message("/thread/1", 1, sha256_hex(body))).signature
        self.assertFalse(self.verify("/thread/1", 1, body, forged))


class MerkleTest(unittest.TestCase):
    def leaves(self, n):
        return [sha256_hex(("file-%d" % i).encode()) for i in range(n)]

    def test_every_leaf_proves_against_the_root(self):
        for count in (1, 2, 3, 5, 8, 17):
            leaves = self.leaves(count)
            root = merkle_root(leaves)
            for index, leaf in enumerate(leaves):
                self.assertTrue(verify_merkle(leaf, merkle_proof(leaves, index), root),
                                "leaf %d of %d" % (index, count))

    def test_a_file_that_is_not_in_the_release_cannot_prove(self):
        leaves = self.leaves(8)
        root = merkle_root(leaves)
        outsider = sha256_hex(b"evil.js")
        self.assertFalse(verify_merkle(outsider, merkle_proof(leaves, 3), root))

    def test_a_tampered_proof_step_fails(self):
        leaves = self.leaves(8)
        root = merkle_root(leaves)
        path = merkle_proof(leaves, 2)
        path[0]["hash"] = sha256_hex(b"substituted")
        self.assertFalse(verify_merkle(leaves[2], path, root))

    def test_the_side_of_each_step_matters(self):
        # A client that guessed the side would verify about half the time, which
        # is worse than failing: it would pass often enough to look correct.
        leaves = self.leaves(8)
        root = merkle_root(leaves)
        path = merkle_proof(leaves, 5)
        flipped = [{"hash": s["hash"],
                    "side": "left" if s["side"] == "right" else "right"} for s in path]
        self.assertFalse(verify_merkle(leaves[5], flipped, root))

    def test_changing_any_file_changes_the_root(self):
        leaves = self.leaves(6)
        root = merkle_root(leaves)
        leaves[4] = sha256_hex(b"file-4-with-a-backdoor")
        self.assertNotEqual(merkle_root(leaves), root)

    def test_the_root_is_stable_for_the_same_input(self):
        leaves = self.leaves(9)
        self.assertEqual(merkle_root(leaves), merkle_root(list(leaves)))


if __name__ == "__main__":
    unittest.main()
