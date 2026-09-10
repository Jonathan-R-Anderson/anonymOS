"""Standing up a restored origin, and telling the network about it.

Item 14 of roadmap/domain-and-origin-succession.md, plus the ordering that makes
the rest of phase 3 safe to run.

WHY A RESTORED ORIGIN GETS A NEW SIGNING KEY
--------------------------------------------
The old one has been sitting inside backups on other people's machines. It is
encrypted there, and the encryption is probably fine — but "probably fine" is
not the standard for the key that decides what this site says. Anyone who ever
held a copy and later learns the passphrase can sign as the site, retroactively
and undetectably, for as long as that key is in use.

Minting a new one costs a directive and a re-pin. Keeping the old one costs
nothing until it costs everything, and there is no way to find out which.

WHAT MINTING A KEY DOES NOT DO
------------------------------
It does not make old content verify. Everything signed by the previous key stops
checking out the moment readers re-pin, so a restored origin has to re-sign what
it intends to keep serving. That is stated here because discovering it after a
restore — when every page fails verification and the obvious conclusion is that
the restore was corrupt — is a bad hour.
"""

import base64

from shared import app


def mint_origin_key():
    """A fresh Ed25519 signing identity for a restored origin.

    Returns both encodings, from ONE key, because they are consumed by different
    things: `services/content_signing` reads a base64 seed from config, and a
    network directive carries the public half as 64 hex characters. Two
    independently-produced values can disagree, and a public key that does not
    match the signer is indistinguishable from an attack.
    """
    from nacl.signing import SigningKey

    key = SigningKey.generate()
    public = bytes(key.verify_key)
    return {
        # Goes into ORIGIN_SIGNING_KEY. Never logged, never stored in the
        # database, never sent to a gateway.
        "private_b64": base64.b64encode(bytes(key)).decode("ascii"),
        # What clients pin, in the encoding each consumer expects.
        "public_b64": base64.b64encode(public).decode("ascii"),
        "public_hex": public.hex(),
    }


def current_origin_public_hex():
    """The public key in force, as a directive would carry it, or ""."""
    try:
        from services.content_signing import public_key_b64

        published = public_key_b64()
        if not published:
            return ""
        return base64.b64decode(published + "=" * (-len(published) % 4)).hex()
    except Exception:
        app.logger.debug("could not read the origin public key", exc_info=True)
        return ""


def restore_checklist(new_domain="", mints_key=True):
    """The order a restore has to happen in, and why each step is where it is.

    Written down because the first time anyone runs this, the site is down, and
    the steps are not guessable — two of them are only correct in one order and
    the failure from getting it wrong is silent.
    """
    steps = [
        {
            "step": "Bring up an empty database and run migrations.",
            "why": "The dump carries rows, not schema. `alembic_version` is "
                   "deliberately excluded, so restoring into an unmigrated "
                   "database would leave Alembic believing the schema is "
                   "current when there is nothing there.",
        },
        {
            "step": "Restore the backup into it, with the passphrase.",
            "why": "Nothing on the old server could open this, which is what "
                   "made it safe to hand to gateways. It also means a lost "
                   "passphrase is a lost backup — there is no recovery path "
                   "and that is the intended trade.",
        },
        {
            "step": "Check the restore report: row counts, and any table in "
                    "the backup that this schema does not have.",
            "why": "A backup from an older build restores with columns dropped "
                   "and tables skipped. That is deliberate — refusing would "
                   "make the artifact useless when it is needed — but it is "
                   "the operator's call whether what was skipped mattered.",
        },
        {
            "step": "Put the carried settings into the new server's config.",
            "why": "TRIPCODE_SECRET especially: it is not in the repo, and a "
                   "new one silently reassigns every persistent identity on "
                   "the site to a different string. Nothing errors.",
        },
    ]
    if mints_key:
        steps.append({
            "step": "Mint a NEW origin signing key. Do not reuse the old one.",
            "why": "The old key sat inside backups on other people's machines. "
                   "Anyone who held a copy and later learns the passphrase can "
                   "sign as this site, and there is no way to detect it.",
        })
        steps.append({
            "step": "Re-sign the content this origin intends to keep serving.",
            "why": "Everything signed by the previous key stops verifying the "
                   "moment readers re-pin. Discovering that after the fact — "
                   "when every page fails and the obvious conclusion is that "
                   "the restore was corrupt — is a bad hour.",
        })
    steps.append({
        "step": "Confirm media loads before announcing anything.",
        "why": "Media is not in the backup; it is content-addressed in the DHT "
               "and fetched by the same hashes. If the new server cannot reach "
               "the DHT, that is visible now and invisible later.",
    })
    steps.append({
        "step": "Issue the directive%s, and watch a node adopt it."
                % (" naming %s" % new_domain if new_domain else ""),
        "why": "This is the irreversible step: nodes restart against whatever "
               "it names. Everything above is recoverable by doing it again; "
               "this is recoverable only by issuing another directive at a "
               "higher sequence, which every node must then see.",
    })
    return steps
