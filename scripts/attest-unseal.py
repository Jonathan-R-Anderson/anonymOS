#!/usr/bin/env python3
"""attest-unseal.py — the gatekeeper's read side; exact twin of scripts/attest-seal.py.

The boot gatekeeper (boot/gatekeeper/init) shells out to this to (1) derive the contract id from the
password+salt, (2) decrypt the eth_call-returned record, and (3) classify the current public IP
against the sealed whitelist/blacklist. It is SELF-CONTAINED AND TESTABLE against attest-seal.py:

    salt=$(python3 scripts/attest-seal.py --password "$PW" --manifest-root ab.. \
             --whitelist 10.0.0.0/8 --id-out /tmp/id --record-out /tmp/rec --salt-out /tmp/salt >/dev/null; cat /tmp/salt)
    printf '%s' "$PW" | python3 scripts/attest-unseal.py --derive-id --salt "$salt"          # == /tmp/id
    printf '{"result":"0x%s"}' "$(python3 - <<'PY'\nimport sys # (wrap /tmp/rec as ABI bytes)\nPY)" | ...  # see --selftest

Run `--selftest` to prove seal→unseal round-trips without any chain. Deps: argon2-cffi, cryptography.
(For the initramfs a C port is lighter than shipping python3+argon2+cryptography — but this defines
the exact bytes it must reproduce.)
"""
import argparse
import hashlib
import ipaddress
import json
import sys

try:
    from argon2.low_level import hash_secret_raw, Type
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError as e:
    sys.exit("attest-unseal: missing dependency (%s). Install: pip install argon2-cffi cryptography" % e)

# MUST match attest-seal.py exactly.
ARGON_TIME, ARGON_MEM_KIB, ARGON_PAR, ARGON_LEN = 3, 64 * 1024, 1, 32
SEAL_VERSION, NONCE_LEN = 1, 12


def derive(password: bytes, salt: bytes):
    km = hash_secret_raw(password, salt, ARGON_TIME, ARGON_MEM_KIB, ARGON_PAR, ARGON_LEN, Type.ID)
    sub = lambda ctx: hashlib.sha256(km + ctx).digest()
    return sub(b"anos-id\0"), sub(b"anos-enc\0")


def derive_key(password: bytes, salt: bytes, ctx: bytes):
    km = hash_secret_raw(password, salt, ARGON_TIME, ARGON_MEM_KIB, ARGON_PAR, ARGON_LEN, Type.ID)
    return hashlib.sha256(km + ctx).digest()


def unseal(key: bytes, blob: bytes) -> bytes:
    if len(blob) < 1 + NONCE_LEN + 16 or blob[0] != SEAL_VERSION:
        raise ValueError("bad seal header")
    return AESGCM(key).decrypt(blob[1:1 + NONCE_LEN], blob[1 + NONCE_LEN:], None)


def abi_decode_bytes(hexresult: str) -> bytes:
    """Decode a single ABI-encoded `bytes` return (offset,len,data) from an eth_call result."""
    h = hexresult[2:] if hexresult.startswith("0x") else hexresult
    if len(h) < 128:
        raise ValueError("eth_call result too short (empty record?)")
    length = int(h[64:128], 16)
    data = h[128:128 + length * 2]
    if len(data) < length * 2:
        raise ValueError("truncated ABI bytes")
    return bytes.fromhex(data)


def classify(ip: str, record: dict) -> str:
    addr = ipaddress.ip_address(ip)
    inlist = lambda L: any(addr in ipaddress.ip_network(c, strict=False) for c in (L or []))
    if inlist(record.get("blacklist")):
        return "BLACKLIST"
    wl = record.get("whitelist") or []
    if not wl:                      # empty whitelist = allow nothing = decoy
        return "DENY"
    return "ALLOW" if inlist(wl) else "DENY"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--derive-id", action="store_true")
    ap.add_argument("--decode-ethcall", action="store_true")
    ap.add_argument("--decrypt-file", help="decrypt an ESP-sealed file (e.g. wpa_supplicant.conf); password on stdin")
    ap.add_argument("--match")
    ap.add_argument("--password")
    ap.add_argument("--salt")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()

    if a.selftest:
        import secrets
        salt = secrets.token_bytes(16)
        _id, ke = derive(b"correct horse battery staple", salt)
        pt = json.dumps({"v": 1, "root": "ab" * 32, "whitelist": ["10.0.0.0/8"],
                         "blacklist": ["5.6.7.8"], "ts": 0}, separators=(",", ":")).encode()
        nonce = secrets.token_bytes(NONCE_LEN)
        blob = bytes([SEAL_VERSION]) + nonce + AESGCM(ke).encrypt(nonce, pt, None)
        rec = json.loads(unseal(ke, blob))
        assert rec["root"] == "ab" * 32
        assert classify("10.1.2.3", rec) == "ALLOW"
        assert classify("5.6.7.8", rec) == "BLACKLIST"
        assert classify("8.8.8.8", rec) == "DENY"
        assert classify("1.2.3.4", {"whitelist": []}) == "DENY"
        # ABI round-trip
        abi = "0x" + "%064x" % 32 + "%064x" % len(blob) + blob.hex() + "00" * ((-len(blob)) % 32)
        assert abi_decode_bytes(abi) == blob
        print("attest-unseal selftest OK")
        return

    salt = bytes.fromhex(a.salt) if a.salt else b""
    if a.derive_id:
        pw = (a.password or sys.stdin.buffer.read().rstrip(b"\n"))
        _id, _ = derive(pw if isinstance(pw, bytes) else pw.encode(), salt)
        print(_id.hex())
        return
    if a.decode_ethcall:
        resp = json.loads(sys.stdin.read())
        blob = abi_decode_bytes(resp["result"])
        _id, ke = derive((a.password or "").encode(), salt)
        sys.stdout.write(unseal(ke, blob).decode())
        return
    if a.decrypt_file:
        pw = a.password.encode() if a.password else sys.stdin.buffer.read().rstrip(b"\n")
        key = derive_key(pw, salt, b"anos-wifi\0")
        sys.stdout.buffer.write(unseal(key, open(a.decrypt_file, "rb").read()))
        return
    if a.match:
        print(classify(a.match, json.loads(sys.stdin.read())))
        return
    ap.error("one of --derive-id / --decode-ethcall / --decrypt-file / --match / --selftest required")


if __name__ == "__main__":
    main()
