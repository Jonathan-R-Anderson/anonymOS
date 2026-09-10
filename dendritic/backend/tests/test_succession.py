"""Standing up a restored origin.

The interesting property is not that a key can be generated — it is that the two
encodings handed to two different consumers describe the SAME key. A public key
that does not match the signer is indistinguishable from an attack, and it is
produced by exactly this kind of helper returning values from separate sources.
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


try:
    from nacl.signing import SigningKey  # noqa: F401
    HAVE_NACL = True
except Exception:
    HAVE_NACL = False

SUC = _load_pure("services/succession.py",
                 {"mint_origin_key", "restore_checklist"},
                 extra={"base64": base64})


@unittest.skipUnless(HAVE_NACL, "PyNaCl is not installed here")
class MintTest(unittest.TestCase):
    def test_the_two_encodings_are_the_same_key(self):
        """They are consumed by different things — content_signing reads a
        base64 seed, a directive carries 64 hex. Two independently-produced
        values can disagree, and a public key that does not match the signer is
        indistinguishable from an attack."""
        minted = SUC["mint_origin_key"]()
        from_b64 = base64.b64decode(minted["public_b64"])
        self.assertEqual(from_b64.hex(), minted["public_hex"])

    def test_the_public_half_really_belongs_to_the_private_one(self):
        from nacl.signing import SigningKey

        minted = SUC["mint_origin_key"]()
        seed = base64.b64decode(minted["private_b64"])
        # content_signing accepts a 32-byte seed or a 64-byte libsodium secret.
        key = SigningKey(seed[:32])
        self.assertEqual(bytes(key.verify_key).hex(), minted["public_hex"])

    def test_it_signs_and_verifies(self):
        from nacl.signing import SigningKey, VerifyKey

        minted = SUC["mint_origin_key"]()
        key = SigningKey(base64.b64decode(minted["private_b64"])[:32])
        signed = key.sign(b"a page")
        VerifyKey(bytes.fromhex(minted["public_hex"])).verify(signed)

    def test_the_hex_is_the_shape_a_directive_accepts(self):
        """origin_key in a directive is validated as 64 lowercase hex."""
        import re

        minted = SUC["mint_origin_key"]()
        self.assertTrue(re.fullmatch(r"[0-9a-f]{64}", minted["public_hex"]))

    def test_every_mint_is_a_different_key(self):
        keys = {SUC["mint_origin_key"]()["public_hex"] for _ in range(5)}
        self.assertEqual(len(keys), 5)


class ChecklistTest(unittest.TestCase):
    """The steps are not guessable and two of them are only correct in one
    order, so the list is part of the feature rather than documentation."""

    def test_migrations_come_before_the_restore(self):
        steps = [entry["step"] for entry in SUC["restore_checklist"]()]
        migrate = next(i for i, s in enumerate(steps) if "migrations" in s)
        load = next(i for i, s in enumerate(steps) if "Restore the backup" in s)
        self.assertLess(migrate, load)

    def test_the_directive_is_last(self):
        """It is the irreversible step. Everything above it can be redone."""
        steps = SUC["restore_checklist"]()
        self.assertIn("directive", steps[-1]["step"])
        self.assertIn("irreversible", steps[-1]["why"])

    def test_minting_a_key_carries_the_re_signing_warning(self):
        """Content signed by the previous key stops verifying the moment
        readers re-pin. Finding that out afterwards looks exactly like a
        corrupt restore."""
        joined = " ".join(entry["step"] + entry["why"]
                          for entry in SUC["restore_checklist"](mints_key=True))
        self.assertIn("Re-sign", joined)
        self.assertNotIn("Re-sign", " ".join(
            entry["step"] for entry in SUC["restore_checklist"](mints_key=False)))

    def test_every_step_says_why(self):
        for entry in SUC["restore_checklist"]("syndichan.net"):
            with self.subTest(step=entry["step"][:40]):
                self.assertGreater(len(entry["why"]), 60)

    def test_the_new_domain_appears_in_the_final_step(self):
        steps = SUC["restore_checklist"]("syndichan.net")
        self.assertIn("syndichan.net", steps[-1]["step"])


if __name__ == "__main__":
    unittest.main()
