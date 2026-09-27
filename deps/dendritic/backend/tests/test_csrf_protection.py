"""CSRF protection on the destructive admin routes.

WHAT IS BEING PINNED
--------------------
Three separate things, because the interesting failure is different for each:

  1. The mechanism. A POST without a token is refused, with a token it works,
     and the refusal is a readable 400 rather than a 500 or a redirect that
     eats the operator's typing.
  2. The coverage. `services.csrf.PROTECTED_ENDPOINTS` is not a comment: every
     endpoint in it must actually carry the decorator, no OTHER endpoint may
     carry it silently, and every form that posts to one must ship the token.
     A protected route whose form forgot the field is an admin control that
     simply stops working, and it would look exactly like a bug in the feature.
  3. The non-coverage. The storage lease/revocation/heartbeat endpoints, the bot
     API, the Stripe webhook and the Falco ingest authenticate with signatures
     and bearer tokens, not with a session cookie. They MUST keep working with
     no CSRF token at all: the heartbeat in particular is what keeps the storage
     network's node census and bootstrap service alive, so protecting it would
     take the DHT offline while looking like a security improvement.

The lease test drives the real blueprint over a real test client rather than
asserting on source, because "it still works" is a claim about a running
request, and the whole risk being managed here is a global switch that quietly
catches an endpoint nobody remembered.
"""

import ast
import base64
import json
import os
import pathlib
import sys
import time
import types
import unittest
from unittest import mock

import flask
from nacl.signing import SigningKey

BACKEND = pathlib.Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from services.csrf import (  # noqa: E402
    FIELD_NAME,
    HEADER_NAME,
    PROTECTED_ENDPOINTS,
    csrf_protect,
    current_token,
    token_input,
)

TEMPLATES = BACKEND / "templates"
ADMIN_SOURCE = (BACKEND / "blueprints" / "admin.py").read_text(encoding="utf-8")

_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58_encode(value):
    leading = len(value) - len(value.lstrip(b"\x00"))
    number = int.from_bytes(value, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = _ALPHABET[remainder] + encoded
    return ("1" * leading) + encoded


def _peer_id(signing_key):
    public_message = b"\x08\x01\x12\x20" + signing_key.verify_key.encode()
    return _base58_encode(b"\x00" + bytes([len(public_message)]) + public_message)


class CsrfMechanismTest(unittest.TestCase):
    """The decorator, driven over a real request."""

    def setUp(self):
        app = flask.Flask("csrf-mechanism-check")
        app.secret_key = "test-secret-not-a-real-one"
        self.destroyed = []

        @app.route("/token")
        def token():
            # What a template does: `{{ csrf_input() }}`.
            return str(token_input())

        @app.route("/destroy", methods=["GET", "POST"])
        @csrf_protect
        def destroy():
            if flask.request.method == "POST":
                self.destroyed.append(flask.request.form.get("target"))
            return "destroyed"

        self.app = app
        self.client = app.test_client()

    def _token(self):
        page = self.client.get("/token").get_data(as_text=True)
        self.assertIn('name="%s"' % FIELD_NAME, page)
        return page.split('value="')[1].split('"')[0]

    def test_a_post_without_a_token_is_refused_and_changes_nothing(self):
        response = self.client.post("/destroy", data={"target": "media:1"})
        self.assertEqual(400, response.status_code)
        self.assertEqual([], self.destroyed,
                         "the view ran even though the token was missing")

    def test_the_refusal_is_readable_and_is_not_a_server_error(self):
        body = self.client.post("/destroy", data={}).get_data(as_text=True)
        self.assertIn("CSRF", body)
        self.assertIn("Reload the page", body)
        self.assertNotIn("Traceback", body)

    def test_a_post_with_the_session_token_succeeds(self):
        token = self._token()
        response = self.client.post(
            "/destroy", data={"target": "media:1", FIELD_NAME: token})
        self.assertEqual(200, response.status_code)
        self.assertEqual(["media:1"], self.destroyed)

    def test_a_token_from_another_session_is_refused(self):
        stranger = self.app.test_client()
        stolen = stranger.get("/token").get_data(as_text=True).split(
            'value="')[1].split('"')[0]
        self._token()  # this client now has a token of its own
        response = self.client.post(
            "/destroy", data={"target": "media:1", FIELD_NAME: stolen})
        self.assertEqual(400, response.status_code)
        self.assertEqual([], self.destroyed)

    def test_the_token_may_arrive_in_a_header_for_fetch_driven_controls(self):
        token = self._token()
        response = self.client.post(
            "/destroy", data={"target": "media:2"}, headers={HEADER_NAME: token})
        self.assertEqual(200, response.status_code)
        self.assertEqual(["media:2"], self.destroyed)

    def test_the_token_is_stable_across_renders(self):
        # Three forms render on the purge page and an operator commonly has a
        # second tab open. A token rotated per request would refuse both.
        self.assertEqual(self._token(), self._token())

    def test_a_get_is_not_blocked(self):
        self.assertEqual(200, self.client.get("/destroy").status_code)

    def test_the_token_is_not_readable_from_the_cookie_by_javascript(self):
        # It lives in the signed session cookie, which the browser marks
        # HttpOnly for this app, rather than in a cookie of its own. Nothing
        # here can prove HttpOnly, but this pins that no second cookie carrying
        # the raw token is created -- which is the mistake that would make the
        # whole scheme a no-op against an XSS-adjacent attacker.
        response = self.client.get("/token")
        token = response.get_data(as_text=True).split('value="')[1].split('"')[0]
        for header in response.headers.getlist("Set-Cookie"):
            self.assertNotIn(token, header,
                             "the raw token is being handed back in a cookie")


class TokenAuthenticatedEndpointsKeepWorkingTest(unittest.TestCase):
    """A signed, non-browser request must not need a CSRF token.

    Driven end to end over the real storage blueprint: this is the endpoint
    family a global CSRFProtect would have broken, and breaking the lease path
    stops the DHT accepting writes.
    """

    def setUp(self):
        from blueprints.storage_nodes import storage_nodes_blueprint

        self.coordinator = SigningKey.generate()
        self.requester = SigningKey.generate()
        self.recipient = SigningKey.generate()
        self.requester_id = _peer_id(self.requester)
        self.recipient_id = _peer_id(self.recipient)
        self.environment = mock.patch.dict(os.environ, {
            "STORAGE_COORDINATOR_SIGNING_KEY":
                base64.b64encode(self.coordinator.encode()).decode("ascii"),
            "STORAGE_LEASE_REQUESTER_PEERS": self.requester_id,
        })
        self.environment.start()

        # The lease now records object ownership; stub the table so this test is
        # about the CSRF question and not about a database.
        self.owners = {}
        stub = types.ModuleType("model.DhtObjectOwner")
        stub.owner_of = lambda object_id: self.owners.get(object_id)
        stub.record_owner = lambda object_id, requester: (
            self.owners.setdefault(object_id, requester), "recorded")
        self._saved = sys.modules.get("model.DhtObjectOwner")
        sys.modules["model.DhtObjectOwner"] = stub

        app = flask.Flask("storage-csrf-check")
        app.secret_key = "test-secret-not-a-real-one"
        app.register_blueprint(storage_nodes_blueprint)
        self.client = app.test_client()

    def tearDown(self):
        self.environment.stop()
        if self._saved is None:
            sys.modules.pop("model.DhtObjectOwner", None)
        else:
            sys.modules["model.DhtObjectOwner"] = self._saved

    def test_a_signed_lease_request_needs_no_csrf_token(self):
        payload = {
            "version": 1,
            "requester": self.requester_id,
            "recipient": self.recipient_id,
            "object_id": "a" * 64,
            "shard_id": "b" * 64,
            "size": 65536,
            "timestamp": int(time.time()),
            "nonce": base64.urlsafe_b64encode(os.urandom(16)).decode("ascii").rstrip("="),
        }
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        signature = base64.b64encode(
            self.requester.sign(raw).signature).decode("ascii").rstrip("=")
        response = self.client.post(
            "/api/v1/storage/leases", data=raw,
            headers={
                "X-Syndichan-Node": self.requester_id,
                "X-Syndichan-Signature": signature,
                "Content-Type": "application/json",
            })
        self.assertEqual(201, response.status_code, response.get_data(as_text=True))
        self.assertIn("signature", response.get_json())


def _decorated_functions(source):
    """{function name: [decorator names]} for every @*.route()'d view."""
    tree = ast.parse(source)
    out = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        names, routed = [], False
        for dec in node.decorator_list:
            if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) \
                    and dec.func.attr == "route":
                routed = True
            elif isinstance(dec, ast.Name):
                names.append(dec.id)
            elif isinstance(dec, ast.Attribute):
                names.append(dec.attr)
        if routed:
            out[node.name] = names
    return out


# These tests read files removed with the stripped features: blueprints/bot_api.py.
#
# SKIPPED CONDITIONALLY RATHER THAN DELETED, matching the civil-rights
# classes in test_evidence_upload.py. The assertions are still correct and
# worth keeping; a skipUnless brings them back the moment the files exist
# again, which a deletion cannot do. PER METHOD, not per class: these
# classes are MIXED, and skipping a whole one destroys its working tests.
_BOT_API_PRESENT = all(
    os.path.exists(os.path.join(BACKEND, part)) for part in (
        "blueprints/bot_api.py",
    )
)
_BOT_API_PRESENT_GONE = "the bot-api blueprint was removed; this reads it"

class ProtectedRouteCoverageTest(unittest.TestCase):
    """PROTECTED_ENDPOINTS is the contract; this is what makes it one."""

    def setUp(self):
        self.admin_views = _decorated_functions(ADMIN_SOURCE)
        self.expected = {name.split(".", 1)[1] for name in PROTECTED_ENDPOINTS
                         if name.startswith("admin.")}

    def test_every_listed_endpoint_exists_and_carries_the_decorator(self):
        for view in sorted(self.expected):
            self.assertIn(view, self.admin_views,
                          "%s is listed as protected but is not a route" % view)
            self.assertIn("csrf_protect", self.admin_views[view],
                          "%s is listed as protected but has no @csrf_protect" % view)

    def test_no_other_admin_route_carries_it_silently(self):
        actual = {name for name, decs in self.admin_views.items()
                  if "csrf_protect" in decs}
        self.assertEqual(
            self.expected, actual,
            "the routes wearing @csrf_protect and the routes PROTECTED_ENDPOINTS "
            "claims are protected have drifted apart")

    def test_the_admin_gate_still_wraps_every_protected_route(self):
        # CSRF is a second lock, never a replacement for the first one.
        for view in sorted(self.expected):
            self.assertIn("_admin_required", self.admin_views[view],
                          "%s lost its admin gate" % view)

    @unittest.skipUnless(_BOT_API_PRESENT, _BOT_API_PRESENT_GONE)
    def test_the_token_authenticated_endpoints_are_not_protected(self):
        for blueprint in ("storage_nodes.py", "bot_api.py", "falco.py"):
            source = (BACKEND / "blueprints" / blueprint).read_text(encoding="utf-8")
            self.assertNotIn(
                "csrf_protect", source,
                "%s authenticates with signatures or bearer tokens; a CSRF token "
                "requirement there refuses every legitimate caller" % blueprint)

    def test_protection_is_per_route_and_not_an_app_wide_switch(self):
        # A global CSRFProtect (or a before_request doing the same job) would
        # catch the heartbeat, the bot API and the webhooks. If one is ever
        # wanted it has to come with an exemption list, and this test is the
        # place that conversation starts.
        for name in ("app.py", "shared.py"):
            source = (BACKEND / name).read_text(encoding="utf-8")
            self.assertNotIn("CSRFProtect", source)
        from services import csrf as csrf_module
        self.assertFalse(
            hasattr(csrf_module, "init_app"),
            "services.csrf grew an app-wide installer; the exemption list for "
            "the signature- and token-authenticated endpoints has to arrive "
            "with it")


class ProtectedFormsCarryTheTokenTest(unittest.TestCase):
    """A protected route whose form forgot the field is a broken admin control.

    It fails closed, which is right, but it fails closed for the OPERATOR, and
    the symptom ("the purge button does nothing") looks nothing like the cause.
    """

    def setUp(self):
        self.forms = []  # (template, form body)
        for path in sorted(TEMPLATES.glob("*.html")):
            text = path.read_text(encoding="utf-8")
            for chunk in text.split("<form")[1:]:
                self.forms.append((path.name, chunk.split("</form>")[0]))

    def test_every_form_posting_to_a_protected_route_ships_the_token(self):
        for template, body in self.forms:
            for endpoint in PROTECTED_ENDPOINTS:
                if "'%s'" % endpoint not in body and '"%s"' % endpoint not in body:
                    continue
                self.assertIn(
                    "csrf_input()", body,
                    "%s has a form posting to %s with no csrf_input(); that "
                    "control is now refused every time it is used"
                    % (template, endpoint))

    # Protected endpoints with no form anywhere, and why each is admitted.
    #
    # An entry here means the endpoint above it proves nothing about that route,
    # so the reason has to say what IS true of it instead. It is not a way to
    # quieten the check: a new protected endpoint that lands with no form still
    # fails, which is the case this test exists for.
    FORMLESS = {
        # TWO admin controls of the same shape: a live POST route, admin-gated
        # AND csrf_protect'd, referenced by NO template and no script. Both
        # forms were in admin templates removed with the rest of the panel.
        #
        # NOT a vulnerability -- both locks are on either route. What they are
        # is destructive admin capability an operator cannot reach: "everything
        # ever imported from one scraped source" and "from every source". The
        # choice between deleting the routes and restoring the forms is a
        # product decision, tracked as OUTSTANDING.md 4.13e rather than settled
        # in a test file.
        #
        # The second one was INVISIBLE until the first was admitted, because
        # assertEqual stops at the first difference it reports. Worth knowing
        # before trusting a green run after adding an exemption.
        "admin.scrapers_purge_all_content":
            "route /scrapers/purge-all is live and doubly gated; its form went "
            "with the admin panel",
        "admin.purge_scraped_source":
            "route /sources/purge is live and doubly gated; its form went with "
            "the admin panel",
    }

    def test_the_scan_is_not_vacuous(self):
        # Every protected endpoint must be reachable from at least one form, or
        # the test above proves nothing about it.
        seen = set()
        for _, body in self.forms:
            for endpoint in PROTECTED_ENDPOINTS:
                if "'%s'" % endpoint in body or '"%s"' % endpoint in body:
                    seen.add(endpoint)
        expected = set(PROTECTED_ENDPOINTS) - set(self.FORMLESS)
        self.assertEqual(expected, seen,
                         "a protected endpoint has no form in any template, so "
                         "nothing checks that its token is being sent. If that "
                         "is deliberate, add it to FORMLESS with the reason.")

    def test_the_formless_list_does_not_outlive_its_endpoints(self):
        """An exemption for a route that no longer exists is a reason nobody
        will re-read, and the next person inherits it as settled fact."""
        for endpoint in self.FORMLESS:
            self.assertIn(endpoint, PROTECTED_ENDPOINTS,
                          "%s is exempted from the form scan but is not a "
                          "protected endpoint any more" % endpoint)


class TokenHelpersTest(unittest.TestCase):
    def test_the_hidden_input_escapes_what_it_renders(self):
        app = flask.Flask("csrf-escape-check")
        app.secret_key = "test-secret-not-a-real-one"
        with app.test_request_context("/"):
            rendered = str(token_input())
            self.assertIn(current_token(), rendered)
            self.assertNotIn("<script", rendered)
            self.assertTrue(rendered.startswith('<input type="hidden"'))
