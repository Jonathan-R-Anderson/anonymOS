"""Cross-site request forgery tokens, applied to the destructive admin routes.

WHY THIS IS NOT A GLOBAL SWITCH
-------------------------------
This application has 288 state-changing routes and no CSRF protection anywhere.
The obvious fix -- `CSRFProtect(app)` -- would cover all 288 at once and break an
unknown number of them, because a large part of that surface does not
authenticate by session cookie at all:

  * `/api/v1/storage/leases`, `/api/v1/storage/revocations` and
    `/api/v1/storage/nodes/heartbeat` are called by Go nodes that sign their
    request body with an ed25519 identity key. They have no cookie jar, no
    session and no way to obtain a token. Breaking the heartbeat takes the whole
    storage network offline -- nodes stop being counted, bootstrap peers stop
    being handed out, and placement stops.
  * `/api/v1/bot/post` authenticates with an IP-locked bearer token.
  * the Stripe webhook authenticates with a signature over the raw body.
  * the Falco ingest authenticates with a shared token.

None of those are forgeable from a browser -- a cross-site request cannot
produce a valid ed25519 signature or a bearer token -- so CSRF protection buys
them nothing, and a global switch would have to be undone for each of them with
an exemption list that is only ever discovered by finding the outage.

So the protection is applied per route, starting with the routes where forgery
is worth something: the ones that destroy content irreversibly. `/admin/dht-purge/recall`
is the one that motivated this -- it deletes shards from OTHER OPERATORS'
machines, and its only defences were the browser's SameSite=Lax default (which
is a default, not a guarantee: it does not exist on old browsers, and it does
not stop a same-site subdomain) and a retype-to-confirm string that for a public
object id is simply the object id, i.e. guessable by anyone who has seen it.

The routes covered are listed in `PROTECTED_ENDPOINTS` below and pinned by a
test, so a new destructive route has to be added to the list deliberately rather
than inherit protection by accident or miss it by accident.

HOW IT FAILS
------------
Closed, with a readable page and HTTP 400 -- not a 500 and not a redirect that
loses the operator's typing. A 500 would be indistinguishable from the purge
itself crashing, which is the one thing an operator must not have to guess about
on this page.

THE TOKEN
---------
A random 32-byte value minted once per session and stored in the Flask session
cookie, which is already signed with the app's secret key. It is compared with
`hmac.compare_digest`. It is deliberately NOT rotated per request: the purge page
renders three forms, an operator commonly has the dashboard open in another tab,
and a per-request token turns both of those into spurious refusals -- which is
how a security control gets switched off.
"""

import hmac
import logging
import secrets
from functools import wraps

from flask import request, session
from markupsafe import Markup, escape


logger = logging.getLogger(__name__)

# The form field, the header and the session key. The header exists so a
# fetch()-driven admin control can be protected without a form.
FIELD_NAME = "csrf_token"
HEADER_NAME = "X-CSRF-Token"
SESSION_KEY = "_csrf_token"

# Methods that can change something. GET/HEAD/OPTIONS are not checked: they are
# supposed to be safe, and a token requirement on them would break every link.
UNSAFE_METHODS = frozenset(("POST", "PUT", "PATCH", "DELETE"))

# Every endpoint this module protects, as `blueprint.view` names. This is
# documentation AND the assertion a test makes -- see tests/test_csrf_protection.py.
#
# The line drawn here is "irreversible destruction of content or accounts,
# including on machines this site does not own". Everything else in the admin
# panel remains unprotected for now; that is a pre-existing hole and it is named
# in the roadmap rather than half-closed here.
PROTECTED_ENDPOINTS = (
    # The DHT purge page. recall/execute destroy bytes on volunteers' machines
    # and in this deployment's own store; preview changes nothing but shares the
    # page, and protecting it keeps one simple invariant -- every POST on the
    # purge page carries a token -- instead of an exception to remember.
    "admin.dht_purge_recall",
    "admin.dht_purge_execute",
    "admin.dht_purge_preview",
    # Media purge: blocklists the hash, deletes from the DHT, deletes the posts.
    "admin.purge_execute",
    # Everything ever imported from one scraped source, on every board.
    "admin.purge_scraped_source",
    # Everything ever imported from every source.
    "admin.scrapers_purge_all_content",
    # An account.
    "admin.delete_slip",
)

# REMOVED 2026-08-20: "admin.delete_board".
#
# There is no longer an HTTP route that deletes a board. `_delete_board` is a
# private helper in blueprints/admin.py and its only caller is
# services/board_cleanup.run_board_cleanup, a background job on a timer -- which
# has no request and therefore no CSRF surface at all.
#
# CHECKED BEFORE REMOVING, because the dangerous version of this edit is the one
# where the capability MOVED to a route that then quietly lost its token: there
# is no other caller, and no route in any blueprint deletes a board under
# another name. The capability is intact and is now reachable only on a timer.
#
# It was listed here while absent from admin.py, which failed three tests in
# tests/test_csrf_protection.py -- the contract naming a route that does not
# exist. Those failures were miscounted as orphans of a deleted feature
# (item 4.13) rather than read as the drift they are.


def current_token():
    """The token for this session, minting one on first use.

    Called from templates via `csrf_token()`. Writing to the session marks it
    modified, so the cookie goes out with the page that carries the form -- the
    token and the cookie that validates it always travel together.
    """
    token = session.get(SESSION_KEY)
    if not isinstance(token, str) or len(token) < 32:
        token = secrets.token_urlsafe(32)
        session[SESSION_KEY] = token
    return token


def token_input():
    """The hidden field, ready to drop inside a <form>. `{{ csrf_input() }}`."""
    # Markup.format escapes its arguments, so a token is never injected raw even
    # though it is generated here rather than received.
    return Markup('<input type="hidden" name="{}" value="{}">').format(
        FIELD_NAME, current_token()
    )


def submitted_token():
    """What the request presented, from the form body or the header."""
    value = request.form.get(FIELD_NAME)
    if not value:
        value = request.headers.get(HEADER_NAME)
    return value or ""


def validate():
    """Return None when the request carries a valid token, else a reason string.

    A reason rather than a boolean because the operator has to be told which of
    the two failures happened: a missing token usually means a stale page, an
    invalid one usually means the session was replaced underneath it, and the
    fix is different.
    """
    expected = session.get(SESSION_KEY)
    presented = submitted_token()
    if not presented:
        return ("This form did not carry a CSRF token. Reload the page and try "
                "again; nothing was changed.")
    if not isinstance(expected, str) or not expected:
        return ("This session has no CSRF token, so the one submitted cannot be "
                "checked. Reload the page and try again; nothing was changed.")
    if not hmac.compare_digest(str(expected), str(presented)):
        return ("The CSRF token did not match this session. Reload the page and "
                "try again; nothing was changed.")
    return None


def _refusal(reason):
    body = (
        "<!doctype html><meta charset=\"utf-8\">"
        "<title>Request refused</title>"
        "<body style=\"font-family:system-ui,sans-serif;max-width:40rem;"
        "margin:4rem auto;line-height:1.5\">"
        "<h1 style=\"font-size:1.4rem\">Request refused</h1>"
        "<p>%s</p>"
        "<p style=\"opacity:.7;font-size:.9rem\">This check exists because the "
        "action you asked for destroys data, in some cases on other operators' "
        "machines, and a page on another site must not be able to ask for it on "
        "your behalf.</p>"
        "</body>" % escape(reason)
    )
    response = (body, 400, {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
    })
    return response


def csrf_protect(view):
    """Refuse an unsafe request that does not carry this session's CSRF token.

    Placed INSIDE the admin gate (`@_admin_required` above it), so a stranger
    gets the ordinary redirect to the login page and a logged-in admin gets a
    page that explains itself.
    """
    @wraps(view)
    def wrapped(*args, **kwargs):
        if request.method in UNSAFE_METHODS:
            reason = validate()
            if reason is not None:
                logger.warning(
                    "csrf: refused %s %s (%s)", request.method, request.path, reason
                )
                return _refusal(reason)
        return view(*args, **kwargs)
    return wrapped
