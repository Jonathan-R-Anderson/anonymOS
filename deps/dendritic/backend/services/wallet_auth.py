"""Wallet (MetaMask) signature challenges and verification.

Signatures are recovered by the renderer sidecar (`RENDERER_HOST/verify/wallet`,
ethers `verifyMessage`) rather than in Python. That is not a stylistic choice:
`eth-account` is listed in backend/requirements.txt but the image installs from
the Pipfile, so it is NOT present at runtime — every code path that imported it
failed with a 501 in production. The renderer path is the one already proven by
admin wallet login.

The recovered address is always treated as authoritative; a client-supplied
address is only ever used as a cross-check. Trusting the claimed address would
let anyone log in as anyone.
"""

import datetime
import secrets
import time

import requests
from flask import session

from shared import app

CHALLENGE_TTL_SECONDS = 300


def normalize_address(address):
    """Lowercase 0x-form, or None if it is not an Ethereum address."""
    if not address:
        return None
    value = str(address).strip().lower()
    if not value.startswith("0x") or len(value) != 42:
        return None
    try:
        int(value, 16)
    except ValueError:
        return None
    return value


def _keys(purpose):
    return "wallet-challenge-%s" % purpose, "wallet-challenge-%s-at" % purpose


def issue_challenge(purpose, statement):
    """Mint a nonce for `purpose` and return the exact message to sign.

    The message states what signing does, so a wallet prompt is never ambiguous
    about which action it authorises — a signature captured for one purpose must
    not be replayable against another, hence the purpose-scoped session key and
    the statement embedded in the signed text.
    """
    nonce = secrets.token_hex(16)
    issued_at = time.time()
    nonce_key, at_key = _keys(purpose)
    session[nonce_key] = nonce
    session[at_key] = issued_at
    return nonce, build_message(statement, nonce, issued_at)


def build_message(statement, nonce, issued_at):
    stamp = datetime.datetime.utcfromtimestamp(issued_at).isoformat() + "Z"
    return "\n".join((
        "%s — %s" % (app.config.get("INSTANCE_NAME", "Syndichan"), statement),
        "Nonce: %s" % nonce,
        "Issued At: %s" % stamp,
        "Signing this proves you control this wallet. It costs no gas and sends no funds.",
    ))


def take_challenge(purpose):
    """Consume the pending challenge, returning (message, error).

    Single-use: the nonce is cleared whether or not verification later succeeds,
    so a captured signature cannot be replayed.
    """
    nonce_key, at_key = _keys(purpose)
    nonce = session.pop(nonce_key, None)
    issued_at = session.pop(at_key, None)
    if not nonce or not issued_at:
        return None, "No active signing challenge — start again."
    if (time.time() - issued_at) > CHALLENGE_TTL_SECONDS:
        return None, "That signing challenge expired — start again."
    return (nonce, issued_at), None


def recover_signer(message, signature, claimed_address=None):
    """Return the address that signed `message`, or None.

    Raises RuntimeError if the verifier is unreachable, so callers can tell
    "signature is wrong" (a user problem) from "we could not check" (ours).
    """
    if not message or not signature:
        return None
    verify_url = app.config["RENDERER_HOST"] + "/verify/wallet"
    probe = normalize_address(claimed_address) or "0x" + "0" * 40
    try:
        response = requests.post(
            verify_url,
            json={"address": probe, "message": message, "signature": signature},
            timeout=10,
        )
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:  # network, non-2xx, or unparseable body
        app.logger.exception("Wallet signature verification unavailable")
        raise RuntimeError("Wallet verification service unavailable") from exc

    recovered = normalize_address(payload.get("recovered_address"))
    if recovered is None:
        return None
    if claimed_address is not None and recovered != normalize_address(claimed_address):
        # The wallet that signed is not the one the page claimed. Not fatal —
        # the recovered address is what counts — but worth a log line, since it
        # is what an account-swap attempt looks like.
        app.logger.info(
            "Wallet signature recovered %s but client claimed %s",
            recovered, normalize_address(claimed_address),
        )
    return recovered
