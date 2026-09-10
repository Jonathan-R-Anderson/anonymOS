import base64
import importlib
import os
import unittest

import nacl.public


class ContentKeysTest(unittest.TestCase):
    def setUp(self):
        # A fixed master so every test is deterministic; reload the module so its
        # per-secret cache starts clean.
        os.environ["STORAGE_CONTENT_MASTER_SECRET"] = "11" * 32
        import services.content_keys as ck

        self.ck = importlib.reload(ck)

    def tearDown(self):
        os.environ.pop("STORAGE_CONTENT_MASTER_SECRET", None)

    def test_bip32_master_matches_reference_vector(self):
        # BIP32 test vector 1 (secp256k1), seed 000102030405060708090a0b0c0d0e0f:
        # master private key e8f3...6b35, chain code 873d...d508.
        os.environ["STORAGE_CONTENT_MASTER_SECRET"] = "000102030405060708090a0b0c0d0e0f"
        self.ck._cache.clear()
        k, chain_code = self.ck._master()
        self.assertEqual(
            k,
            int("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35", 16),
        )
        self.assertEqual(
            chain_code.hex(),
            "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
        )

    def test_derivation_is_deterministic_and_per_object(self):
        a1 = self.ck._child_scalar("lab/alpha")
        a2 = self.ck._child_scalar("lab/alpha")
        b = self.ck._child_scalar("lab/beta")
        self.assertEqual(a1, a2)
        self.assertNotEqual(a1, b)

    def test_encrypt_decrypt_round_trip(self):
        plaintext = b"compose project bytes \x00\x01\x02" * 100
        blob = self.ck.encrypt("lab/alpha", plaintext)
        self.assertTrue(blob.startswith(b"SCE1"))
        self.assertNotIn(plaintext, blob)  # ciphertext, not plaintext
        self.assertEqual(self.ck.decrypt(blob), plaintext)

    def test_each_encrypt_is_fresh_but_recoverable(self):
        # Random ephemeral + content key each call -> different bytes, both decrypt.
        one = self.ck.encrypt("media/x", b"hello")
        two = self.ck.encrypt("media/x", b"hello")
        self.assertNotEqual(one, two)
        self.assertEqual(self.ck.decrypt(one), b"hello")
        self.assertEqual(self.ck.decrypt(two), b"hello")

    def test_worker_grant_round_trip(self):
        # The server seals the content key to a worker's Curve25519 key; only that
        # worker can open it (mirrors Go's nacl/box.OpenAnonymous).
        worker = nacl.public.PrivateKey.generate()
        worker_pub = bytes(worker.public_key)
        plaintext = b"vulhub compose tar"
        blob = self.ck.encrypt("lab/alpha", plaintext)

        sealed = base64.b64decode(self.ck.seal_for_worker(blob, worker_pub))
        content_key = nacl.public.SealedBox(worker).decrypt(sealed)
        self.assertEqual(len(content_key), 32)

        # The recovered key really is the one that decrypts the content.
        self.assertEqual(content_key, self.ck._recover_key(blob))

    def test_wrong_worker_cannot_open_grant(self):
        worker = nacl.public.PrivateKey.generate()
        intruder = nacl.public.PrivateKey.generate()
        blob = self.ck.encrypt("lab/alpha", b"secret")
        sealed = base64.b64decode(
            self.ck.seal_for_worker(blob, bytes(worker.public_key))
        )
        with self.assertRaises(Exception):
            nacl.public.SealedBox(intruder).decrypt(sealed)

    def test_tampered_ciphertext_fails(self):
        blob = bytearray(self.ck.encrypt("lab/alpha", b"payload"))
        blob[-1] ^= 0xFF  # flip a ciphertext byte
        with self.assertRaises(Exception):
            self.ck.decrypt(bytes(blob))

    def test_different_master_cannot_decrypt(self):
        blob = self.ck.encrypt("lab/alpha", b"payload")
        os.environ["STORAGE_CONTENT_MASTER_SECRET"] = "22" * 32
        self.ck._cache.clear()
        with self.assertRaises(Exception):
            self.ck.decrypt(blob)


if __name__ == "__main__":
    unittest.main()
