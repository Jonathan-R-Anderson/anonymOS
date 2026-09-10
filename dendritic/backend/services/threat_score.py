"""Score a request, and say why.

The score is the boring half. The REASONS are what makes this usable: a number
nobody can argue with is a number that gets ignored when it is right and
defended when it is wrong, and the person a false positive lands on is the one
least able to reach anyone about it.

So every signal returns `(points, why)` and the why is stored alongside the
decision — stored, not recomputed. A reason reconstructed later from rules that
have since changed is not the reason the decision actually used, and an incident
review that reads a plausible reconstruction as fact is worse than one with no
explanation at all.

WHAT THIS DELIBERATELY DOES NOT DO
----------------------------------
It does not block. It does not challenge. It does not publish. Phase 1 of
`roadmap/wall-of-shame.md` scores and records what WOULD have happened, because
thresholds picked before seeing real traffic are guesses, and a scorer shipped
with guessed thresholds blocks readers before it blocks attackers.

It also does not learn from its own output. "Continuously learn from observed
attacks" is in the specification, and a system trained on its own blocks
amplifies its own mistakes with nothing outside to correct it.
"""

import re

# Bands from the specification. Named rather than inlined so the admin view, the
# tests and any future enforcement all read the same boundaries.
BAND_SAFE = "safe"
BAND_MONITOR = "monitor"
BAND_CHALLENGE = "challenge"
BAND_BLOCK = "block"

BANDS = (
    (0, 25, BAND_SAFE),
    (26, 50, BAND_MONITOR),
    (51, 75, BAND_CHALLENGE),
    (76, 100, BAND_BLOCK),
)


def band_for(score):
    for low, high, name in BANDS:
        if low <= score <= high:
            return name
    return BAND_BLOCK if score > 100 else BAND_SAFE


# Paths a machine must reach for the network to work. A scorer that blocks
# gateway registration or the audit intake breaks the thing it protects, and it
# would do so exactly when a gateway is behaving unusually — which is what
# registration and attestation traffic looks like.
#
# Mirrors the `auth_request off` convention already used for Anubis: the same
# endpoints, for the same reason.
EXEMPT_PREFIXES = (
    "/api/v1/gateways",
    "/api/v1/gateway/",
    "/api/v1/storage/",
    "/api/v1/pof/",
    "/api/v1/snapshot/",
    "/.well-known/",
    "/snapshot/object/",
    "/falco/ingest/",
    "/health",
    "/metrics",
)


def is_exempt(path):
    lowered = (path or "").lower()
    return any(lowered.startswith(prefix) for prefix in EXEMPT_PREFIXES)


# -- signals ---------------------------------------------------------------
#
# Each returns (points, reason) or (0, None). Points are deliberately modest:
# no single signal should reach a blocking band alone, because every one of them
# has a benign explanation and the combination is what carries information.

_SQLI = re.compile(
    r"(\bunion\b.{0,20}\bselect\b|\bselect\b.{0,20}\bfrom\b.{0,30}\bwhere\b"
    r"|\bor\b\s+1\s*=\s*1|'\s*or\s*'|\bsleep\s*\(|\bbenchmark\s*\("
    r"|\bwaitfor\s+delay\b|\binformation_schema\b|\bxp_cmdshell\b)", re.I)

_XSS = re.compile(
    r"(<script\b|javascript:|onerror\s*=|onload\s*=|<iframe\b|document\.cookie"
    r"|<svg\b[^>]*onload)", re.I)

_TRAVERSAL = re.compile(r"(\.\./|\.\.%2f|%2e%2e/|/etc/passwd|/proc/self/environ"
                        r"|\bboot\.ini\b|c:\\windows)", re.I)

_CMDI = re.compile(r"(;\s*(cat|ls|id|whoami|curl|wget|nc|bash|sh)\b"
                   r"|\|\s*(cat|sh|bash)\b|\$\(.*\)|`.*`)", re.I)

_SSRF = re.compile(r"(https?://(127\.|10\.|192\.168\.|169\.254\.|localhost|\[::1\])"
                   r"|file://|gopher://|dict://)", re.I)

# Paths that exist only to be scanned for. Hitting one is not proof of malice —
# a security researcher and a botnet look identical here — but nothing on this
# site links to them.
_SCANNER_PATHS = re.compile(
    r"^/(wp-admin|wp-login|wp-content|wordpress|xmlrpc\.php|phpmyadmin|pma"
    r"|\.env|\.git/|\.aws/|config\.php|admin\.php|shell\.php|cgi-bin/"
    r"|vendor/phpunit|solr/|struts|jenkins|actuator/|\.DS_Store)", re.I)


def signal_injection(path, query, body_preview=""):
    """Injection signatures anywhere in the request line."""
    haystack = "%s?%s %s" % (path or "", query or "", body_preview or "")
    for pattern, points, name in (
        (_SQLI, 30, "SQL injection signature"),
        (_CMDI, 30, "command injection signature"),
        (_TRAVERSAL, 25, "directory traversal signature"),
        (_XSS, 20, "cross-site scripting signature"),
        (_SSRF, 20, "SSRF signature"),
    ):
        if pattern.search(haystack):
            return points, name
    return 0, None


def signal_scanner_path(path):
    if _SCANNER_PATHS.search(path or ""):
        return 20, "requested a path that exists only on other software"
    return 0, None


def signal_user_agent(user_agent):
    """A missing or tool-shaped user agent.

    Small on purpose. Plenty of legitimate clients send an odd agent, and any
    attacker who cares will send a browser's. This is weak evidence and is
    priced as weak evidence.
    """
    agent = (user_agent or "").strip()
    if not agent:
        return 10, "no user agent"
    lowered = agent.lower()
    for marker in ("sqlmap", "nikto", "nmap", "masscan", "zgrab", "dirbuster",
                   "gobuster", "wpscan", "hydra", "havij", "acunetix"):
        if marker in lowered:
            return 35, "self-identified scanning tool (%s)" % marker
    if len(agent) < 8:
        return 5, "implausibly short user agent"
    return 0, None


def signal_malformed(path, headers):
    """Protocol-level oddities that a browser does not produce."""
    if path and ("\x00" in path or "\n" in path or "\r" in path):
        return 30, "control characters in the request path"
    if path and len(path) > 2048:
        return 15, "excessively long request path"
    duplicated = [name for name in ("host", "content-length")
                  if isinstance(headers, dict) and _count_header(headers, name) > 1]
    if duplicated:
        # Duplicate Host or Content-Length is the shape of request smuggling.
        return 35, "duplicate %s header" % duplicated[0]
    return 0, None


def _count_header(headers, name):
    return sum(1 for key in headers if key.lower() == name)


def signal_rate(recent_requests, window_seconds):
    """Volume from one client in a window.

    Banded rather than linear so an enthusiastic reader and a flood are told
    apart. A person clicking quickly reaches the first band; nothing a human
    does with a browser reaches the last.
    """
    if not window_seconds or recent_requests <= 0:
        return 0, None
    per_second = recent_requests / float(window_seconds)
    if per_second >= 50:
        return 40, "%.0f requests/second sustained" % per_second
    if per_second >= 20:
        return 25, "%.0f requests/second sustained" % per_second
    if per_second >= 8:
        return 12, "%.0f requests/second sustained" % per_second
    return 0, None


def signal_not_found_scanning(recent_404s, window_seconds):
    """Repeated misses — the shape of enumeration.

    A reader following a stale link produces one. A scanner produces hundreds,
    and produces almost nothing else.
    """
    if recent_404s >= 50:
        return 30, "%d not-found responses in %ds" % (recent_404s, window_seconds)
    if recent_404s >= 15:
        return 18, "%d not-found responses in %ds" % (recent_404s, window_seconds)
    return 0, None


def signal_login_pressure(recent_failed_logins):
    if recent_failed_logins >= 20:
        return 35, "%d failed authentication attempts" % recent_failed_logins
    if recent_failed_logins >= 6:
        return 18, "%d failed authentication attempts" % recent_failed_logins
    return 0, None


def score_request(request_features):
    """Return ``{"score", "band", "reasons", "exempt"}``.

    Reasons are ordered by weight, so the top line of an incident view is the
    thing that actually drove the decision rather than whichever check ran first.
    """
    path = request_features.get("path") or ""
    if is_exempt(path):
        return {"score": 0, "band": BAND_SAFE, "exempt": True,
                "reasons": [{"points": 0, "why": "machine endpoint, not scored"}]}

    signals = [
        signal_injection(path, request_features.get("query"),
                         request_features.get("body_preview")),
        signal_scanner_path(path),
        signal_user_agent(request_features.get("user_agent")),
        signal_malformed(path, request_features.get("headers") or {}),
        signal_rate(int(request_features.get("recent_requests") or 0),
                    int(request_features.get("window_seconds") or 0)),
        signal_not_found_scanning(int(request_features.get("recent_404s") or 0),
                                  int(request_features.get("window_seconds") or 0)),
        signal_login_pressure(int(request_features.get("recent_failed_logins") or 0)),
    ]

    reasons = [{"points": points, "why": why} for points, why in signals if why]
    reasons.sort(key=lambda entry: -entry["points"])
    # Capped at 100 so the bands stay meaningful. An uncapped total would put
    # every serious offender in one indistinguishable pile above the top band,
    # and "how bad" is a question the wall will need to answer.
    score = min(100, sum(entry["points"] for entry in reasons))
    return {"score": score, "band": band_for(score), "exempt": False,
            "reasons": reasons}
