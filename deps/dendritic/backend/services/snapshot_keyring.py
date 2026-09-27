"""Which publisher keys are legitimate — decided by a key the server never holds.

Every signature in this system so far is only as good as the key that made it,
and until now there was no answer to "what happens when that key is stolen". The
answer is an offline ROOT key that signs a registry of operational keys, and
never touches the machine that uses them.

    root key       offline, on paper or a hardware token   signs the registry
    publisher key  on the build host, used constantly      signs snapshots

WHAT THIS SERVER CAN AND CANNOT DO
----------------------------------
It can serve a registry. It CANNOT make one — there is deliberately no signing
path here, because a root key stored next to the thing it is supposed to protect
is not a root key, it is a second copy of the publisher key with extra steps.

So compromising this server yields the ability to sign snapshots, which is
already true, and NOT the ability to declare a new publisher key legitimate. That
distinction is the entire value: a stolen publisher key can be revoked by an
operator with the root key, from a machine the attacker never touched, and every
gateway will stop honouring it without anybody logging into anything.

WHY THE REGISTRY IS SIGNED RATHER THAN CONFIGURED
-------------------------------------------------
Gateways could pin the publisher key directly — and one does, today. But then
rotating it means every operator editing a config by hand, so in practice it
never rotates, and a key that cannot be rotated is one that will eventually be
compromised and stay that way. Pinning the ROOT and letting it delegate means
rotation is an announcement rather than a coordination problem.

SEE ALSO
--------
`roadmap/gateway-validation.md` lists "a compromised origin key" as unsolved.
This is the missing piece, and it is worth using for that key too rather than
building the same thing twice.
"""

import base64
import datetime
import json

from shared import app

ROOT_PREFIX = b"syndichan-keyring:v1"
SETTING_KEYRING = "snapshot_keyring"

# The root public key gateways pin. Configuration, not a secret — publishing it
# is the point. The PRIVATE half must never appear in this repository, in .env,
# or on any server that serves traffic.
CONFIG_ROOT_PUBLIC = "SNAPSHOT_ROOT_PUBLIC_KEY"


def _unb64(text):
    return base64.b64decode(str(text or "").strip() + "===")


def root_public_key():
    return (app.config.get(CONFIG_ROOT_PUBLIC) or "").strip() or None


def keyring_message(root_sequence, publisher_keys, revoked_keys, issued_at):
    """The exact bytes the offline root key signs.

    Both key lists are sorted, so a registry rebuilt by a gateway produces the
    same bytes regardless of how it was serialised on the way here.
    """
    return b"\n".join([
        ROOT_PREFIX,
        str(int(root_sequence)).encode("ascii"),
        ",".join(sorted(str(k) for k in publisher_keys)).encode("ascii"),
        ",".join(sorted(str(k) for k in revoked_keys)).encode("ascii"),
        str(int(issued_at)).encode("ascii"),
    ])


def verify_keyring(record, root_public=None):
    """Check a registry against the pinned root key. Never raises."""
    public = root_public or root_public_key()
    if not public or not record or not record.get("signature"):
        return False
    try:
        from nacl.signing import VerifyKey

        message = keyring_message(
            record.get("root_sequence") or 0,
            [entry.get("public_key") for entry in (record.get("publisher_keys") or [])],
            record.get("revoked_keys") or [],
            record.get("issued_at") or 0)
        VerifyKey(_unb64(public)).verify(message, _unb64(record["signature"]))
        return True
    except Exception:
        return False


def current_keyring():
    """The published registry, or None when none has been installed."""
    from model.SiteSetting import get_setting

    try:
        stored = json.loads(get_setting(SETTING_KEYRING, "") or "{}")
    except ValueError:
        return None
    return stored or None


def install_keyring(record):
    """Store a registry signed elsewhere. Returns (ok, reason).

    Verified before storing, and refused if its sequence does not advance. An
    attacker who reaches this server could otherwise reinstall an OLD registry
    to bring a revoked key back — the same rollback the snapshot sequence exists
    to stop, one level up.
    """
    from model.SiteSetting import set_setting

    if not verify_keyring(record):
        return False, ("not signed by the configured root key (or "
                       "SNAPSHOT_ROOT_PUBLIC_KEY is unset)")
    current = current_keyring() or {}
    try:
        incoming = int(record.get("root_sequence") or 0)
        existing = int(current.get("root_sequence") or 0)
    except (TypeError, ValueError):
        return False, "root_sequence must be a number"
    if current and incoming <= existing:
        return False, ("root_sequence %d does not advance past the installed %d; "
                       "reinstalling an older registry would restore revoked keys"
                       % (incoming, existing))
    set_setting(SETTING_KEYRING, json.dumps(record))
    app.logger.warning("snapshot keyring: installed registry %d (%d key(s), %d revoked)",
                       incoming, len(record.get("publisher_keys") or []),
                       len(record.get("revoked_keys") or []))
    return True, "installed"


def publisher_key_is_valid(public_key_b64, now=None):
    """Whether a publisher key is currently delegated by the root.

    No registry installed means TRUE: a deployment that has not adopted key
    rotation yet must keep working, and the pinned publisher key is still the
    check that matters there. Once a registry exists it is authoritative, and a
    key that is absent from it or listed as revoked is refused.
    """
    record = current_keyring()
    if not record or not verify_keyring(record):
        return True
    if public_key_b64 in set(record.get("revoked_keys") or []):
        return False
    moment = int((now or datetime.datetime.utcnow()).timestamp())
    for entry in record.get("publisher_keys") or []:
        if entry.get("public_key") != public_key_b64:
            continue
        valid_from = int(entry.get("valid_from") or 0)
        valid_until = int(entry.get("valid_until") or 0)
        if valid_from and moment < valid_from:
            return False
        if valid_until and moment > valid_until:
            return False
        return True
    return False
