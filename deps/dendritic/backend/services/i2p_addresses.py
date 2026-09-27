"""Strict validation for routable I2P Base32 destinations."""

import re


I2P_HOST_RE = re.compile(r"^[a-z2-7]{52}\.b32\.i2p$")


def normalize_i2p_host(host):
    host = str(host or "").strip().lower().rstrip(".")
    if not I2P_HOST_RE.fullmatch(host):
        raise ValueError("Peer host must be a 52-character Base32 .b32.i2p destination.")
    return host


def is_i2p_host(host):
    try:
        normalize_i2p_host(host)
        return True
    except ValueError:
        return False
