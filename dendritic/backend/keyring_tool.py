"""Sign a publisher-key registry with the offline root key.

RUN THIS ON A MACHINE THAT DOES NOT SERVE TRAFFIC.

    python3 keyring_tool.py --genroot
    python3 keyring_tool.py --sign --root-key <seed> --sequence 1 \
        --publisher <base64-key>:2026-01-01:2027-01-01 [--revoke <base64-key>]

The whole value of the root key is that it lives somewhere the attacker does
not. A root key on the web server is not a root key — it is a second copy of the
publisher key with extra ceremony, and it would let anyone who reached that
server declare their own key legitimate.

So this tool imports NOTHING from the application: no Flask, no database, no
config. It reads arguments, does arithmetic, and prints JSON. That is what
allows it to be run from a laptop that has never been online, with the output
pasted into the admin page.
"""

import argparse
import base64
import datetime
import json
import sys

ROOT_PREFIX = b"syndichan-keyring:v1"


def _b64(raw):
    return base64.b64encode(raw).decode("ascii")


def keyring_message(root_sequence, publisher_keys, revoked_keys, issued_at):
    """Must match services/snapshot_keyring.keyring_message exactly."""
    return b"\n".join([
        ROOT_PREFIX,
        str(int(root_sequence)).encode("ascii"),
        ",".join(sorted(str(k) for k in publisher_keys)).encode("ascii"),
        ",".join(sorted(str(k) for k in revoked_keys)).encode("ascii"),
        str(int(issued_at)).encode("ascii"),
    ])


def _parse_publisher(value):
    """`key[:valid_from[:valid_until]]`, dates as YYYY-MM-DD."""
    parts = value.split(":")
    entry = {"public_key": parts[0], "valid_from": 0, "valid_until": 0}
    for index, name in ((1, "valid_from"), (2, "valid_until")):
        if len(parts) > index and parts[index].strip():
            parsed = datetime.datetime.strptime(parts[index].strip(), "%Y-%m-%d")
            entry[name] = int(parsed.replace(
                tzinfo=datetime.timezone.utc).timestamp())
    return entry


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--genroot", action="store_true",
                        help="print a new root keypair and exit")
    parser.add_argument("--sign", action="store_true")
    parser.add_argument("--root-key", help="base64 root private seed")
    parser.add_argument("--sequence", type=int, default=0,
                        help="root_sequence; MUST increase every time")
    parser.add_argument("--publisher", action="append", default=[],
                        help="key[:valid_from[:valid_until]], repeatable")
    parser.add_argument("--revoke", action="append", default=[],
                        help="a publisher key that must no longer be honoured")
    args = parser.parse_args()

    from nacl.signing import SigningKey

    if args.genroot:
        key = SigningKey.generate()
        print("# ROOT PRIVATE SEED — never put this on a server, in .env, or in git.")
        print("# Store it offline. Losing it means you can never rotate again;")
        print("# leaking it means an attacker can declare their own publisher key.")
        print(_b64(bytes(key)))
        print()
        print("# Public half — put this in .env as SNAPSHOT_ROOT_PUBLIC_KEY and")
        print("# pin it in every gateway configuration.")
        print("SNAPSHOT_ROOT_PUBLIC_KEY=%s" % _b64(bytes(key.verify_key)))
        return 0

    if not args.sign or not args.root_key:
        parser.print_help()
        return 2
    if args.sequence <= 0:
        print("--sequence must be a positive number that INCREASES every time; "
              "reinstalling an older registry would restore revoked keys",
              file=sys.stderr)
        return 2

    seed = base64.b64decode(args.root_key.strip() + "===")
    if len(seed) == 64:
        seed = seed[:32]
    signer = SigningKey(seed)

    publishers = [_parse_publisher(value) for value in args.publisher]
    issued_at = int(datetime.datetime.utcnow().timestamp())
    message = keyring_message(args.sequence,
                              [entry["public_key"] for entry in publishers],
                              args.revoke, issued_at)
    record = {
        "schema": 1,
        "root_sequence": args.sequence,
        "publisher_keys": publishers,
        "revoked_keys": list(args.revoke),
        "issued_at": issued_at,
        "signature": _b64(signer.sign(message).signature),
    }
    print(json.dumps(record, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
