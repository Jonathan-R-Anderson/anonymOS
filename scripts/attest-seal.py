#!/usr/bin/env python3
"""attest-seal.py — client-side seal for the EncryptedAttestationVault (contracts/).

Reference implementation of the crypto + wire format that the installer, the boot gatekeeper, and
the mobile app MUST all agree on. It:

  1. derives  km = Argon2id(password, salt)   (memory-hard; params below are the shared contract)
  2. splits   id  = SHA256(km ‖ "anos-id\0")   -> the on-chain key (contract get/put)
              kEnc = SHA256(km ‖ "anos-enc\0")  -> AES-256-GCM key for the on-chain record
              kLoc = SHA256(km ‖ "anos-loc\0")  -> AES-256-GCM key for the local full manifest
  3. seals the COMPACT on-chain record  = 0x01 ‖ nonce(12) ‖ AES256GCM(kEnc, json{root,whitelist,blacklist,ts})
  4. seals the LOCAL full manifest       = 0x01 ‖ nonce(12) ‖ AES256GCM(kLoc, json{files:{path:hash}})
  5. writes the salt (random, per-install) — it lives LOCALLY on the ESP so the gatekeeper can
     re-derive id/kEnc from the password BEFORE it can fetch the record.

There is NO operator key and NO recovery: only this password reproduces id/kEnc/kLoc.

Wire format (version byte 0x01): SEAL = b"\\x01" + nonce[12] + ciphertext_with_gcm_tag.
On-chain plaintext (JSON, compact):
  {"v":1,"root":"<hex sha256 of the file-manifest>","whitelist":["1.2.3.4","10.0.0.0/8"],
   "blacklist":["5.6.7.8"],"ts":<unix>}

Deps: argon2-cffi, cryptography.  !!! UNTESTED in this environment — review + run the self-check
(`--selftest`) on a trusted host before trusting it with real records.
"""

import argparse
import hashlib
import ipaddress
import json
import os
import secrets
import sys
import time

try:
    from argon2.low_level import hash_secret_raw, Type
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError as e:
    sys.exit("attest-seal: missing dependency (%s). Install: pip install argon2-cffi cryptography" % e)

# ── shared KDF contract — MUST be identical in the gatekeeper and the mobile app ─────────────
ARGON_TIME = 3
ARGON_MEM_KIB = 64 * 1024      # 64 MiB
ARGON_PAR = 1
ARGON_LEN = 32
SEAL_VERSION = 1
SALT_LEN = 16
NONCE_LEN = 12


def derive(password: bytes, salt: bytes):
    km = hash_secret_raw(password, salt, ARGON_TIME, ARGON_MEM_KIB, ARGON_PAR, ARGON_LEN, Type.ID)
    sub = lambda ctx: hashlib.sha256(km + ctx).digest()
    return sub(b"anos-id\0"), sub(b"anos-enc\0"), sub(b"anos-loc\0")


def seal(key: bytes, plaintext: bytes) -> bytes:
    nonce = secrets.token_bytes(NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return bytes([SEAL_VERSION]) + nonce + ct


def unseal(key: bytes, blob: bytes) -> bytes:
    if len(blob) < 1 + NONCE_LEN + 16 or blob[0] != SEAL_VERSION:
        raise ValueError("bad seal header")
    nonce = blob[1:1 + NONCE_LEN]
    return AESGCM(key).decrypt(nonce, blob[1 + NONCE_LEN:], None)


def _valid_ips(items):
    out = []
    for s in items:
        s = s.strip()
        if not s:
            continue
        ipaddress.ip_network(s, strict=False)   # raises on malformed
        out.append(s)
    return out


def main():
    ap = argparse.ArgumentParser(description="Seal an EpinAnonymOS attestation record.")
    ap.add_argument("--password", help="install password (omit to prompt; env ATTEST_PASSWORD also works)")
    ap.add_argument("--manifest-root", help="hex SHA-256 of the file manifest (from build-boot-integrity-manifest.py)")
    ap.add_argument("--manifest-file", help="JSON {path:hash,...} of ALL system files (sealed locally)")
    ap.add_argument("--whitelist", default="", help="comma-separated allowed IPs/CIDRs")
    ap.add_argument("--blacklist", default="", help="comma-separated denied IPs/CIDRs")
    ap.add_argument("--salt", help="hex salt (omit to generate; MUST be stored on the ESP)")
    ap.add_argument("--record-out", help="write the on-chain SEAL here (hex)")
    ap.add_argument("--id-out", help="write the contract id here (hex)")
    ap.add_argument("--salt-out", help="write the salt here (hex) — goes on the ESP")
    ap.add_argument("--local-out", help="write the sealed full local manifest here (hex)")
    ap.add_argument("--selftest", action="store_true", help="round-trip self-check and exit")
    args = ap.parse_args()

    if args.selftest:
        salt = secrets.token_bytes(SALT_LEN)
        _id, ke, kl = derive(b"correct horse battery staple", salt)
        pt = json.dumps({"v": 1, "root": "ab" * 32, "whitelist": ["10.0.0.0/8"], "blacklist": [], "ts": 0},
                        separators=(",", ":")).encode()
        blob = seal(ke, pt)
        assert unseal(ke, blob) == pt, "roundtrip failed"
        try:
            unseal(kl, blob); sys.exit("selftest FAILED: wrong key decrypted")
        except Exception:
            pass
        print("selftest OK (Argon2id %d MiB/t=%d, AES-256-GCM, seal v%d)" % (ARGON_MEM_KIB // 1024, ARGON_TIME, SEAL_VERSION))
        return

    pw = args.password or os.environ.get("ATTEST_PASSWORD")
    if not pw:
        import getpass
        pw = getpass.getpass("install password: ")
    if len(pw) < 12:
        sys.exit("attest-seal: refuse weak password (< 12 chars) — the sealed record is public forever")
    if not args.manifest_root:
        sys.exit("attest-seal: --manifest-root required")

    salt = bytes.fromhex(args.salt) if args.salt else secrets.token_bytes(SALT_LEN)
    _id, kEnc, kLoc = derive(pw.encode(), salt)

    record_pt = json.dumps({
        "v": 1,
        "root": args.manifest_root.lower(),
        "whitelist": _valid_ips(args.whitelist.split(",")),
        "blacklist": _valid_ips(args.blacklist.split(",")),
        "ts": int(time.time()),
    }, separators=(",", ":")).encode()
    record = seal(kEnc, record_pt)
    if len(record) > 8192:
        sys.exit("attest-seal: sealed record %d B exceeds the contract's 8192 B cap" % len(record))

    def emit(path, hexbytes):
        if path:
            open(path, "w").write(hexbytes if isinstance(hexbytes, str) else hexbytes.hex())

    emit(args.id_out, _id)
    emit(args.record_out, record)
    emit(args.salt_out, salt)
    if args.manifest_file and args.local_out:
        emit(args.local_out, seal(kLoc, open(args.manifest_file, "rb").read()))

    print("id=%s" % _id.hex())
    print("salt=%s   (store on the ESP)" % salt.hex())
    print("record=%d bytes sealed" % len(record))
    if not (args.id_out or args.record_out):
        print("record_hex=%s" % record.hex())


if __name__ == "__main__":
    main()
