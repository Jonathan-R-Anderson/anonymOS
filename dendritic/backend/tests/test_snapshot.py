"""Emergency snapshots: what they must refuse to publish, and what a reader can check.

A snapshot is served when nothing else works, to people who cannot tell it apart
from the live site except by what it says. So the tests worth writing are about
the ways a snapshot could be worse than no snapshot at all:

  * an interactive control that silently swallows what somebody typed;
  * a session token frozen into a public artifact;
  * a signature that verifies for content it does not cover;
  * an old snapshot replayed over a newer one.
"""

import base64
import os
import pathlib
import sys
import unittest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)


def _load_pure(relative_path, wanted, extra=None):
    """Exec only the named definitions, skipping module-level app imports."""
    import ast

    source = (pathlib.Path(BACKEND) / relative_path).read_text()
    tree = ast.parse(source)
    keep = [node for node in tree.body
            if (isinstance(node, ast.Assign)
                and {t.id for t in node.targets if isinstance(t, ast.Name)} & wanted)
            or (isinstance(node, ast.FunctionDef) and node.name in wanted)]
    module = ast.Module(body=keep, type_ignores=[])
    ast.fix_missing_locations(module)
    namespace = dict(extra or {})
    exec(compile(module, relative_path, "exec"), namespace)
    return namespace


class ManifestSignatureTest(unittest.TestCase):
    """The signature must cover everything that changes what a snapshot means."""

    def module(self):
        return _load_pure("services/snapshot_key.py",
                          {"manifest_message", "SNAPSHOT_PREFIX"})

    def sign(self, key, **fields):
        message = self.module()["manifest_message"](**fields)
        return message, base64.b64encode(key.sign(message).signature).decode()

    def fields(self, **overrides):
        base = {"snapshot_id": "abc123", "sequence": 8841, "root": "deadbeef",
                "created_at": 1785500000, "expires_at": 1785586400, "count": 42}
        base.update(overrides)
        return base

    def test_a_signature_does_not_transfer_between_snapshots(self):
        from nacl.signing import SigningKey, VerifyKey

        key = SigningKey.generate()
        message, signature = self.sign(key, **self.fields())
        VerifyKey(bytes(key.verify_key)).verify(
            message, base64.b64decode(signature))   # the honest case

        # Each of these changes what the snapshot claims, so each must break it.
        for field, value in [("sequence", 8840), ("root", "cafebabe"),
                             ("expires_at", 9999999999), ("count", 41),
                             ("snapshot_id", "other")]:
            forged = self.module()["manifest_message"](**self.fields(**{field: value}))
            with self.assertRaises(Exception, msg="%s is not covered by the signature" % field):
                VerifyKey(bytes(key.verify_key)).verify(
                    forged, base64.b64decode(signature))

    def test_the_prefix_separates_snapshots_from_other_signatures(self):
        # Without a distinct prefix, an origin-object signature could be
        # replayed as a snapshot manifest signature or the reverse.
        prefix = self.module()["SNAPSHOT_PREFIX"]
        self.assertEqual(prefix, b"syndichan-snapshot:v1")
        self.assertNotIn(b"object", prefix)


class PublisherKeySeparationTest(unittest.TestCase):
    """The publisher key must never silently become the origin key."""

    def source(self):
        return (pathlib.Path(BACKEND) / "services" / "snapshot_key.py").read_text()

    def test_it_never_falls_back_to_the_origin_key(self):
        # A fallback would undo the separation at exactly the moment somebody
        # was in a hurry, and the deployment would look correct.
        source = self.source()
        self.assertNotIn("ORIGIN_SIGNING_KEY", source)
        self.assertNotIn("content_signing", source)

    def test_unset_means_unsigned_rather_than_signed_by_something_else(self):
        module = _load_pure("services/snapshot_key.py", {"CONFIG_PRIVATE", "CONFIG_PUBLIC"})
        self.assertEqual(module["CONFIG_PRIVATE"], "SNAPSHOT_SIGNING_KEY")
        self.assertNotEqual(module["CONFIG_PRIVATE"], "ORIGIN_SIGNING_KEY")


class BannerMarkerTest(unittest.TestCase):
    """The banner carries a class pages can detect. That is a contract."""

    def banner(self):
        source = (pathlib.Path(BACKEND) / "services" / "snapshot_banner.py").read_text()
        namespace = {}
        exec(compile(source, "snapshot_banner.py", "exec"), namespace)
        return namespace

    def test_the_banner_is_findable_from_the_page(self):
        """/network switches its own download off when it sees this class.

        The rewriter disables forms and buttons, but it cannot know that a plain
        link points at something only the origin can answer. So the page checks
        for the banner itself — and if this class is ever dropped from the
        markup, that check silently starts returning false and the download
        button comes back to life during an outage, offering a file nobody can
        fetch. The class and the constant are asserted together so neither can
        drift away from the other unnoticed.
        """
        namespace = self.banner()
        self.assertEqual(namespace["BANNER_CLASS"], "dendritic-emergency-banner")
        self.assertIn('class="%s"' % namespace["BANNER_CLASS"],
                      namespace["BANNER_HTML"])

    def test_the_page_that_depends_on_it_still_looks_for_it(self):
        template = (pathlib.Path(BACKEND) / "templates" / "network.html")
        if not template.exists():
            self.skipTest("network.html is not present")
        self.assertIn(self.banner()["BANNER_CLASS"], template.read_text())

    def test_the_banner_needs_no_stylesheet(self):
        """It is shown when things are broken. It cannot depend on assets."""
        self.assertIn("style=", self.banner()["BANNER_HTML"])


class ReadOnlyRewriteTest(unittest.TestCase):
    """A cached page must not look like it still works."""

    def module(self):
        import ast

        source = (pathlib.Path(BACKEND) / "services" / "snapshot_rewrite.py").read_text()
        tree = ast.parse(source)
        keep = [n for n in tree.body
                if not (isinstance(n, ast.ImportFrom)
                        and n.module == "services.snapshot_banner")]
        module = ast.Module(body=keep, type_ignores=[])
        ast.fix_missing_locations(module)
        namespace = {"BANNER_HTML": "<div>SNAPSHOT %s</div>",
                     "DISABLED_NOTICE": "disabled"}
        exec(compile(module, "snapshot_rewrite.py", "exec"), namespace)
        return namespace

    def rewrite(self, html):
        module = self.module()
        out, _took_away = module["rewrite_html"](html, "1 January 2026")
        return module, out

    def rewrite_full(self, html):
        """(module, html, took_something_away) — for the phase 6 contract."""
        module = self.module()
        out, took_away = module["rewrite_html"](html, "1 January 2026")
        return module, out, took_away

    def test_it_needs_no_third_party_parser(self):
        # The first version used BeautifulSoup, which is not in the backend
        # image, so every page silently failed to rewrite and the whole
        # snapshot was refused. This code produces the artifact served WHEN
        # THINGS ARE BROKEN; the fewer things it needs, the fewer ways it has
        # to be missing exactly then.
        import ast

        source = (pathlib.Path(BACKEND) / "services" / "snapshot_rewrite.py").read_text()
        # Checked by IMPORT, not by searching the text: the docstring explains
        # why BeautifulSoup is absent, and that explanation is worth keeping.
        imported = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertNotIn("bs4", imported)
        self.assertIn("html", imported)

    def test_forms_are_replaced_not_merely_disabled(self):
        # A disabled control whose stylesheet failed to load still looks
        # clickable, and a missing stylesheet is exactly what happens in the
        # situation this exists for.
        module, out = self.rewrite(
            "<html><body><form action='/post' method='post'>"
            "<input name='body'><button>Post</button></form></body></html>")
        self.assertFalse(module["looks_interactive"](out))
        self.assertNotIn("/post", out)

    def test_session_tokens_never_reach_a_published_snapshot(self):
        _, out = self.rewrite(
            "<html><head><meta name='csrf-token' content='SECRET'></head>"
            "<body><input name='csrf_token' value='TOKEN'></body></html>")
        self.assertNotIn("TOKEN", out)
        self.assertNotIn("SECRET", out)

    def test_buttons_outside_a_form_are_disabled_too(self):
        # Script-wired buttons survive form replacement, and the script cannot
        # reach the origin either — so a live one reads as a broken site rather
        # than an offline one.
        _, out = self.rewrite(
            "<html><body><button onclick='vote()'>Upvote</button></body></html>")
        self.assertIn("disabled", out)
        self.assertNotIn("onclick", out)

    def test_a_page_that_lost_something_is_labelled(self):
        _, out, took = self.rewrite_full(
            "<html><body><form action='/post'><button>Post</button></form></body></html>")
        self.assertTrue(took)
        self.assertIn("1 January 2026", out)

    def test_a_page_that_lost_nothing_is_left_exactly_alone(self):
        # This is what phase 6 rests on. A FAQ loses no form, no token, no
        # handler — so the stored bytes ARE the origin's bytes, and serving them
        # from cache while the origin is up misleads nobody and removes nothing.
        # A banner here would be a lie: the page is not an emergency copy.
        html = "<html><body><p>hello</p></body></html>"
        _, out, took = self.rewrite_full(html)
        self.assertFalse(took)
        self.assertEqual(out, html)
        self.assertNotIn("1 January 2026", out)

    def test_a_form_inside_a_comment_is_not_a_form(self):
        # Regression: the refusal check was a substring search, so an inert
        # <form> written inside an HTML comment dropped a good page from every
        # snapshot forever, blaming the rewriter. It is parsed now — which is
        # the same reason the rewriter itself is not a regex.
        module, out = self.rewrite(
            "<html><body><p>a <!-- <form> --> b</p></body></html>")
        self.assertFalse(module["looks_interactive"](out))
        self.assertIn("<form>", out)

    def test_a_leftover_live_form_is_still_caught(self):
        # Guards the test above: a check that returned False for everything
        # would pass it while defending nothing.
        module = self.module()
        self.assertTrue(module["looks_interactive"]("<p><form action=/x></form></p>"))

    def test_entities_and_comments_survive_intact(self):
        _, out = self.rewrite(
            "<html><body><p>a &amp; b <!-- keep --></p></body></html>")
        self.assertIn("&amp;", out)
        self.assertIn("keep", out)


class ContentAddressingTest(unittest.TestCase):
    """Names are hashes, so storage can never quietly substitute content."""

    def module(self):
        import hashlib
        return _load_pure("services/snapshot.py", {"sha256_hex"},
                          extra={"hashlib": hashlib})

    def test_identical_bytes_are_one_object(self):
        digest = self.module()["sha256_hex"]
        self.assertEqual(digest(b"same"), digest(b"same"))

    def test_one_changed_byte_is_a_different_object(self):
        digest = self.module()["sha256_hex"]
        self.assertNotEqual(digest(b"<p>hello</p>"), digest(b"<p>hellp</p>"))


class RefusalTest(unittest.TestCase):
    """A snapshot of a broken site is worse than no snapshot."""

    def test_a_minimum_route_count_is_enforced(self):
        # The failure this prevents: the hour the origin starts erroring is the
        # hour a snapshot of error pages replaces the last good copy.
        module = _load_pure("services/snapshot.py", {"MINIMUM_ROUTES"})
        self.assertGreaterEqual(module["MINIMUM_ROUTES"], 3)

    def test_eligibility_reuses_the_existing_privacy_boundary(self):
        # A second exclusion list would drift from viewer_can_use_public_cache,
        # and the drift would be somebody's private board published to
        # strangers rather than a rendering bug.
        source = (pathlib.Path(BACKEND) / "services" / "snapshot.py").read_text()
        self.assertIn("viewer_can_use_public_cache", source)

    def test_expiry_is_bounded(self):
        module = _load_pure("services/snapshot.py",
                            {"REFRESH_AFTER_HOURS", "STALE_AFTER_HOURS",
                             "EXPIRES_AFTER_HOURS"})
        self.assertLess(module["REFRESH_AFTER_HOURS"], module["STALE_AFTER_HOURS"])
        self.assertLess(module["STALE_AFTER_HOURS"], module["EXPIRES_AFTER_HOURS"])


class ClientVerificationTest(unittest.TestCase):
    """The browser path, checked by reading what it actually does."""

    def source(self):
        return (pathlib.Path(BACKEND) / "static" / "js" / "verify-origin.js").read_text()

    def test_a_snapshot_claim_is_not_taken_on_trust(self):
        # The header selects the verification path; the manifest signature
        # decides the outcome. If the header alone could suppress checking, a
        # tampering gateway would set it first.
        source = self.source()
        self.assertIn("X-Syndichan-Source", source)
        self.assertIn("verifySnapshot", source)
        self.assertIn("syndichan-snapshot:v1", source)

    def test_a_verified_snapshot_reports_pass_not_stale(self):
        # Otherwise every outage looks like a fleet of gateways going bad at
        # once, and the audit record exists to tell those apart.
        source = self.source()
        start = source.index("function checkSnapshot")
        body = source[start:start + 4000]
        self.assertIn('"pass"', body)

    def test_snapshot_rollback_is_still_refused(self):
        source = self.source()
        self.assertIn("syndichan.snapshot-sequence", source)
        self.assertIn("rollback", source.lower())


if __name__ == "__main__":
    unittest.main()


class BuilderProcessTest(unittest.TestCase):
    """The builder must run inside the serving process, not beside it.

    Running it as a second process means importing the app again, which re-runs
    the startup DDL against a database the live process is already using. Those
    statements take AccessExclusiveLock; doing it once deadlocked the serving
    process and took the pod down, AFTER publishing a perfectly good snapshot.
    """

    def test_the_cli_no_longer_imports_the_app(self):
        import ast

        source = (pathlib.Path(BACKEND) / "build_snapshot.py").read_text()
        imported = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        for forbidden in ("app", "shared", "services"):
            self.assertNotIn(forbidden, imported,
                             "importing %s starts a second application" % forbidden)

    def test_there_is_an_in_process_entry_point(self):
        source = (pathlib.Path(BACKEND) / "services" / "snapshot.py").read_text()
        self.assertIn("def build_and_publish", source)
        source = (pathlib.Path(BACKEND) / "blueprints" / "admin.py").read_text()
        self.assertIn("/snapshot/build", source)


class ControlRecordTest(unittest.TestCase):
    """Revocation and defensive mode: levers that can be pulled and then lost."""

    def module(self):
        return _load_pure("services/snapshot_control.py",
                          {"revocation_message", "defensive_message",
                           "REVOCATION_PREFIX", "DEFENSIVE_PREFIX",
                           "MAX_DEFENSIVE_SECONDS"})

    def test_a_revocation_signature_covers_its_own_sequence(self):
        # Without it, replaying a validly signed EMPTY list would un-revoke
        # everything — the cheapest possible attack on a revocation system.
        from nacl.signing import SigningKey, VerifyKey

        message = self.module()["revocation_message"]
        key = SigningKey.generate()
        real = message([7], [], 5, 1785500000)
        signature = key.sign(real).signature
        replayed = message([], [], 4, 1785500000)
        with self.assertRaises(Exception):
            VerifyKey(bytes(key.verify_key)).verify(replayed, signature)

    def test_revocation_lists_are_sorted_before_signing(self):
        # A signature over an unordered set is a signature over whichever order
        # happened to be produced, and a gateway rebuilding it must get the
        # same bytes.
        message = self.module()["revocation_message"]
        self.assertEqual(message([9, 7, 8], [], 1, 0), message([7, 8, 9], [], 1, 0))

    def test_defensive_mode_signature_covers_its_expiry(self):
        # Otherwise a captured record could be replayed with a later deadline
        # and hold the site read-only indefinitely.
        from nacl.signing import SigningKey, VerifyKey

        message = self.module()["defensive_message"]
        key = SigningKey.generate()
        real = message("DHT_CACHE_ONLY", "overload", 1785500000, 1785503600, 0)
        signature = key.sign(real).signature
        extended = message("DHT_CACHE_ONLY", "overload", 1785500000, 9999999999, 0)
        with self.assertRaises(Exception):
            VerifyKey(bytes(key.verify_key)).verify(extended, signature)

    def test_defensive_mode_has_a_hard_ceiling(self):
        # "Read-only because nobody can find the control key" is a worse outage
        # than any it prevents, so the lever falls back on its own.
        ceiling = self.module()["MAX_DEFENSIVE_SECONDS"]
        self.assertGreater(ceiling, 0)
        self.assertLessEqual(ceiling, 24 * 3600)

    def test_the_two_records_cannot_be_confused(self):
        module = self.module()
        self.assertNotEqual(module["REVOCATION_PREFIX"], module["DEFENSIVE_PREFIX"])


class RetentionTest(unittest.TestCase):
    """Garbage collection must not delete what a retained snapshot still uses."""

    def module(self):
        return _load_pure("services/snapshot_store.py",
                          {"RETAINED_SNAPSHOTS", "GC_GRACE_SECONDS"})

    def test_more_than_one_snapshot_is_retained(self):
        # Keeping only the active one means a malformed newest snapshot has
        # nothing to roll back to.
        self.assertGreaterEqual(self.module()["RETAINED_SNAPSHOTS"], 3)

    def test_collection_waits_out_a_grace_period(self):
        # A gateway that fetched a manifest a moment before it was superseded
        # must still be able to finish the download it started.
        self.assertGreaterEqual(self.module()["GC_GRACE_SECONDS"], 3600)

    def test_objects_are_collected_by_reference_not_age(self):
        # Content addressing means an object is shared between snapshots, so
        # deleting by age would delete the unchanged CSS every retained
        # snapshot still points at.
        source = (pathlib.Path(BACKEND) / "services" / "snapshot_store.py").read_text()
        self.assertIn("_remove_unreferenced", source)
        self.assertIn("referenced", source)


class DeltaPublishingTest(unittest.TestCase):
    """Transfer only what changed — and verify everything regardless."""

    def delta(self):
        return _load_pure("services/snapshot.py", {"_delta"})["_delta"]

    def manifest(self, routes):
        return {"routes": {path: {"object": digest} for path, digest in routes.items()}}

    def test_an_unchanged_site_transfers_nothing(self):
        # The property that makes publishing cheap enough to do OFTEN, which is
        # what a snapshot-first architecture needs to serve current content.
        previous = self.manifest({"/": "aaa", "/faq": "bbb"})
        current = self.manifest({"/": "aaa", "/faq": "bbb"})
        changed, unchanged = self.delta()(previous, current)
        self.assertEqual(changed, set())
        self.assertEqual(len(unchanged), 2)

    def test_only_modified_objects_are_new(self):
        previous = self.manifest({"/": "aaa", "/faq": "bbb"})
        current = self.manifest({"/": "aaa", "/faq": "CHANGED"})
        changed, unchanged = self.delta()(previous, current)
        self.assertEqual(changed, {"CHANGED"})
        self.assertEqual(unchanged, {"aaa"})

    def test_a_page_that_moved_path_is_not_a_transfer(self):
        # Compared by object hash, not by route: the same bytes at a new path
        # are already stored, because the name IS the hash.
        previous = self.manifest({"/old": "aaa"})
        current = self.manifest({"/new": "aaa"})
        changed, _ = self.delta()(previous, current)
        self.assertEqual(changed, set())

    def test_the_first_snapshot_is_all_new(self):
        changed, unchanged = self.delta()({}, self.manifest({"/": "aaa"}))
        self.assertEqual(changed, {"aaa"})
        self.assertEqual(unchanged, set())

    def test_verification_still_covers_every_object(self):
        # Transfer is the delta; verification is not. An unchanged object that
        # vanished from the store would otherwise sail through, and the gap
        # would surface only when a reader asked for that page mid-outage.
        source = (pathlib.Path(BACKEND) / "services" / "snapshot.py").read_text()
        publish_call = source[source.index("if not publish(manifest,"):]
        self.assertTrue(publish_call.startswith("if not publish(manifest, objects)"),
                        "publish() must receive the full object set, not the delta")


class SearchIndexTest(unittest.TestCase):
    """Search must survive the outage, and must not overstate what it covers."""

    def module(self):
        import re
        return _load_pure("services/snapshot_search.py",
                          {"build_index", "words_in", "text_of", "title_of",
                           "_WORD", "_STOPWORDS", "_TAG", "_SCRIPT",
                           "MAX_WORDS_PER_PAGE", "MAX_INDEX_WORDS"},
                          extra={"re": re})

    def test_it_finds_a_page_by_a_word_on_it(self):
        module = self.module()
        index = module["build_index"]({
            "/boards/tech": "<html><body><p>quantum computing thread</p></body></html>",
            "/faq": "<html><body><p>frequently asked questions</p></body></html>",
        })
        self.assertIn("quantum", index["index"])
        route = index["routes"][index["index"]["quantum"][0]]
        self.assertEqual(route, "/boards/tech")

    def test_script_and_style_contents_are_not_indexed(self):
        # Indexing a stylesheet fills the index with selector fragments nobody
        # will ever search for, at the cost of every reader's download.
        module = self.module()
        text = module["text_of"](
            "<html><style>.cls{color:red}</style><script>var x=1</script>"
            "<p>visible</p></html>")
        self.assertIn("visible", text)
        self.assertNotIn("color", text)
        self.assertNotIn("var", text)

    def test_one_page_cannot_inflate_the_index(self):
        # A dictionary dump or a pasted wordlist must not bloat a file every
        # reader downloads.
        module = self.module()
        huge = " ".join("word%d" % i for i in range(5000))
        self.assertLessEqual(len(module["words_in"]("<p>%s</p>" % huge)),
                             module["MAX_WORDS_PER_PAGE"])

    def test_the_index_is_deterministic(self):
        # Otherwise it looks "changed" on every build and defeats the delta it
        # lives alongside.
        module = self.module()
        pages = {"/a": "<p>alpha beta</p>", "/b": "<p>beta gamma</p>"}
        self.assertEqual(module["build_index"](pages), module["build_index"](pages))

    def test_routes_are_referenced_by_position_not_repeated(self):
        # A route repeated under every word it contains would make the index
        # several times larger than the pages it describes.
        module = self.module()
        index = module["build_index"]({"/long/route/name": "<p>alpha beta gamma</p>"})
        for postings in index["index"].values():
            for entry in postings:
                self.assertIsInstance(entry, int)

    def test_it_says_what_it_does_not_cover(self):
        # A confident result over an incomplete corpus is worse than an
        # obviously partial list: anything posted since the snapshot is absent.
        module = self.module()
        index = module["build_index"]({"/": "<p>hello</p>"})
        self.assertIn("absent", index["note"].lower())

    def test_it_is_shipped_as_an_ordinary_snapshot_object(self):
        # Signed and deduplicated by the same machinery as a page, with no
        # special case to get wrong.
        source = (pathlib.Path(BACKEND) / "services" / "snapshot.py").read_text()
        self.assertIn("/snapshot/search-index.json", source)
        self.assertIn("_search_index_body", source)


class SequenceDurabilityTest(unittest.TestCase):
    """A sequence that is not committed is a rollback vulnerability.

    set_setting writes to the session; a request flushes it at teardown and a
    background caller does not. Every snapshot published as sequence 1, which
    means BOTH "rollback protection is void" and "no gateway will ever take a
    new snapshot" — while the logs report a successful publish every hour.
    """

    def test_next_sequence_commits(self):
        source = (pathlib.Path(BACKEND) / "services" / "snapshot.py").read_text()
        body = source[source.index("def next_sequence"):]
        body = body[:body.index("\ndef ", 1)]
        self.assertIn("commit", body,
                      "the sequence counter must be made durable explicitly")

    def test_control_records_commit(self):
        source = (pathlib.Path(BACKEND) / "services" / "snapshot_control.py").read_text()
        self.assertIn("_commit", source)
        for function in ("def revoke", "def declare_defensive_mode",
                         "def clear_defensive_mode"):
            body = source[source.index(function):]
            body = body[:body.index("\ndef ", 1) if "\ndef " in body[1:] else len(body)]
            self.assertIn("_commit", body,
                          "%s must persist, or it is applied only in memory" % function)


class ReissueTest(unittest.TestCase):
    """An idle site must cost a signature, not a full re-upload."""

    def module(self):
        return _load_pure("services/snapshot.py",
                          {"_content_is_unchanged", "_delta"})

    def manifest(self, routes):
        return {"routes": {path: {"object": obj, "source_hash": src}
                           for path, (obj, src) in routes.items()}}

    def test_a_changed_banner_alone_is_not_a_content_change(self):
        # THE bug this exists for: the banner names the build time, so a
        # rewritten page differs on every build. Comparing rewritten bytes would
        # report every page as changed and make every rebuild a full re-upload.
        previous = self.manifest({"/": ("obj-built-at-10am", "src-aaa")})
        rebuilt = self.manifest({"/": ("obj-built-at-11am", "src-aaa")})
        self.assertTrue(self.module()["_content_is_unchanged"](previous, rebuilt))

    def test_a_real_edit_is_a_content_change(self):
        # Guards the test above: a comparison that always said "unchanged" would
        # pin a stale snapshot forever while passing it.
        previous = self.manifest({"/": ("obj-1", "src-aaa")})
        rebuilt = self.manifest({"/": ("obj-2", "src-bbb")})
        self.assertFalse(self.module()["_content_is_unchanged"](previous, rebuilt))

    def test_adding_or_removing_a_route_is_a_change(self):
        module = self.module()
        previous = self.manifest({"/": ("o", "s")})
        added = self.manifest({"/": ("o", "s"), "/new": ("o2", "s2")})
        self.assertFalse(module["_content_is_unchanged"](previous, added))
        self.assertFalse(module["_content_is_unchanged"](added, previous))

    def test_an_older_manifest_without_source_hashes_counts_as_changed(self):
        # The safe direction: costs one rebuild rather than pinning a stale
        # snapshot because a field was missing.
        module = self.module()
        previous = {"routes": {"/": {"object": "o"}}}
        rebuilt = self.manifest({"/": ("o", "s")})
        self.assertFalse(module["_content_is_unchanged"](previous, rebuilt))

    def test_a_reissue_keeps_the_previous_root(self):
        # Signing the rebuilt root would commit to objects nobody stored.
        source = (pathlib.Path(BACKEND) / "services" / "snapshot.py").read_text()
        body = source[source.index("def _reissue"):]
        body = body[:body.index("\ndef ", 1)]
        self.assertIn('manifest["root_hash"]', body)
        self.assertNotIn('rebuilt["root_hash"]', body)


class PerRouteReuseTest(unittest.TestCase):
    """One busy board must not force a full re-upload."""

    def module(self):
        import hashlib
        # _reroot re-signs, which needs the app. Stubbed to a passthrough: this
        # class tests which OBJECT each route ends up pointing at, and a
        # separate test asserts that _reroot is called at all.
        return _load_pure("services/snapshot.py",
                          {"_reuse_unchanged", "_delta", "sha256_hex"},
                          extra={"hashlib": hashlib,
                                 "_reroot": lambda manifest: manifest})

    def previous(self):
        return {"routes": {
            "/": {"object": "old-home", "source_hash": "src-home"},
            "/faq": {"object": "old-faq", "source_hash": "src-faq"},
        }}

    def test_an_unchanged_route_keeps_its_existing_object(self):
        # The rewritten body carries a banner naming the build time, so a page
        # nobody edited still produces new bytes every build. Reusing the stored
        # copy is both cheaper AND more accurate: its banner names when that
        # copy was actually taken.
        module = self.module()
        rebuilt = {"routes": {
            "/": {"object": "new-home-rewritten", "source_hash": "src-home"},
            "/faq": {"object": "new-faq-rewritten", "source_hash": "src-faq"},
        }}
        objects = {"new-home-rewritten": b"a", "new-faq-rewritten": b"b"}
        manifest, remaining = module["_reuse_unchanged"](self.previous(), rebuilt, objects)
        self.assertEqual(manifest["routes"]["/"]["object"], "old-home")
        self.assertEqual(manifest["routes"]["/faq"]["object"], "old-faq")
        self.assertEqual(remaining, {}, "nothing should need uploading")

    def test_a_genuinely_changed_route_keeps_its_new_object(self):
        module = self.module()
        rebuilt = {"routes": {
            "/": {"object": "new-home", "source_hash": "CHANGED"},
            "/faq": {"object": "new-faq", "source_hash": "src-faq"},
        }}
        objects = {"new-home": b"a", "new-faq": b"b"}
        manifest, remaining = module["_reuse_unchanged"](self.previous(), rebuilt, objects)
        self.assertEqual(manifest["routes"]["/"]["object"], "new-home")
        self.assertEqual(manifest["routes"]["/faq"]["object"], "old-faq")
        self.assertEqual(set(remaining), {"new-home"},
                         "only the edited page should be uploaded")

    def test_the_root_is_recomputed_over_what_is_actually_published(self):
        # The root commits to the routes. Reusing an object changes a route, so
        # a root computed before the swap would commit to objects that are not
        # in the manifest — and every reader's verification would fail.
        source = (pathlib.Path(BACKEND) / "services" / "snapshot.py").read_text()
        body = source[source.index("def _reuse_unchanged"):]
        body = body[:body.index("\ndef _delta")]
        self.assertIn("_reroot", body)


class QuorumTest(unittest.TestCase):
    """Several publishers signing one snapshot, and the ways that gets faked."""

    def module(self):
        return _load_pure("services/snapshot_quorum.py",
                          {"attestation_message", "QUORUM_PREFIX", "DEFAULTS",
                           "_why"})

    def test_coverage_is_inside_the_signed_message(self):
        # If it sat beside the signature, a publisher could sign once and then
        # claim any coverage it liked — and the number that makes this honest
        # would be the one thing unprotected.
        from nacl.signing import SigningKey, VerifyKey

        message = self.module()["attestation_message"]
        key = SigningKey.generate()
        honest = message("snap", 7, "root", 5, 7)
        signature = key.sign(honest).signature
        inflated = message("snap", 7, "root", 7, 7)
        with self.assertRaises(Exception):
            VerifyKey(bytes(key.verify_key)).verify(inflated, signature)

    def test_an_attestation_does_not_transfer_between_snapshots(self):
        from nacl.signing import SigningKey, VerifyKey

        message = self.module()["attestation_message"]
        key = SigningKey.generate()
        signature = key.sign(message("snap-7", 7, "root-a", 5, 7)).signature
        for other in (message("snap-8", 7, "root-a", 5, 7),
                      message("snap-7", 8, "root-a", 5, 7),
                      message("snap-7", 7, "root-b", 5, 7)):
            with self.assertRaises(Exception):
                VerifyKey(bytes(key.verify_key)).verify(other, signature)

    def test_defaults_demand_more_than_one_operator(self):
        # A default of 1 would silently disable the only real protection: keys
        # are free, so counting keys is satisfied by one compromised machine.
        defaults = self.module()["DEFAULTS"]
        self.assertGreater(defaults["snapshot_quorum_operators"], 1)
        self.assertGreater(defaults["snapshot_quorum_min_coverage_pct"], 0)

    def test_signatures_from_one_operator_are_reported_as_such(self):
        module = self.module()
        why = module["_why"]([{"operator": "a"}, {"operator": "a"}], {"a"},
                             module["DEFAULTS"], True, False)
        self.assertIn("one operator", why.lower())

    def test_the_prefix_cannot_be_confused_with_other_records(self):
        control = _load_pure("services/snapshot_control.py",
                             {"REVOCATION_PREFIX", "DEFENSIVE_PREFIX"})
        keyring = _load_pure("services/snapshot_keyring.py", {"ROOT_PREFIX"})
        quorum = self.module()["QUORUM_PREFIX"]
        self.assertNotIn(quorum, {control["REVOCATION_PREFIX"],
                                  control["DEFENSIVE_PREFIX"],
                                  keyring["ROOT_PREFIX"]})


class SourceRootTest(unittest.TestCase):
    """The reproducible commitment must not be the served one."""

    def test_the_manifest_carries_both_roots(self):
        # root_hash covers served objects, which carry a build-time banner and
        # legitimately differ between publishers. source_root covers what the
        # SITE produced, which is what independent parties can attest to.
        source = (pathlib.Path(BACKEND) / "services" / "snapshot.py").read_text()
        self.assertIn('"root_hash": root', source)
        self.assertIn('"source_root"', source)

    def test_reroot_keeps_the_source_root_consistent(self):
        # Reusing an object changes a route, so a source root computed before
        # the swap would commit to something the manifest no longer describes.
        source = (pathlib.Path(BACKEND) / "services" / "snapshot.py").read_text()
        body = source[source.index("def _reroot"):]
        body = body[:body.index("\ndef ", 1)]
        self.assertIn("source_root", body)


class OffloadEligibilityTest(unittest.TestCase):
    """Which routes a gateway may serve while the origin is UP.

    Both conditions are necessary, and each guards a different harm:
      * volatile content served stale shows readers a board missing the last
        hour of posts, which is worse than a slow page;
      * a page that lost its post box, served while the origin is fine, takes
        away somebody's ability to post with no way to tell why.
    """

    def module(self):
        return _load_pure("services/snapshot.py",
                          {"_mark_offloadable", "OFFLOAD_STABLE_BUILDS"})

    def run_builds(self, count, source="src", offload_object="raw"):
        module = self.module()
        previous = {}
        for _ in range(count):
            manifest = {"routes": {"/faq": {"source_hash": source,
                                            "offload_object": offload_object}}}
            module["_mark_offloadable"](previous, manifest)
            previous = manifest
        return previous["routes"]["/faq"]

    def test_one_quiet_build_is_not_enough(self):
        # A single unchanged build is what a busy board looks like between two
        # posts, not evidence that a page is stable.
        self.assertFalse(self.run_builds(1)["offload"])

    def test_repeated_stability_earns_offload(self):
        entry = self.run_builds(self.module()["OFFLOAD_STABLE_BUILDS"] + 1)
        self.assertTrue(entry["offload"])

    def test_a_route_with_no_untouched_variant_is_never_offloaded(self):
        # Without one there is nothing to serve but the emergency copy, and
        # handing a reader a disabled search box while the origin is fine
        # removes a capability they still have.
        entry = self.run_builds(10, offload_object=None)
        self.assertGreaterEqual(entry["stable_builds"],
                                self.module()["OFFLOAD_STABLE_BUILDS"])
        self.assertFalse(entry["offload"])

    def test_a_change_resets_the_count(self):
        # A page that just changed is exactly the page a reader most wants live.
        module = self.module()
        previous = {"routes": {"/faq": {"source_hash": "old", "stable_builds": 99}}}
        manifest = {"routes": {"/faq": {"source_hash": "new",
                                        "offload_object": "raw"}}}
        module["_mark_offloadable"](previous, manifest)
        self.assertEqual(manifest["routes"]["/faq"]["stable_builds"], 0)
        self.assertFalse(manifest["routes"]["/faq"]["offload"])

    def test_the_threshold_is_more_than_one(self):
        self.assertGreater(self.module()["OFFLOAD_STABLE_BUILDS"], 1)

    def test_marking_happens_after_routes_are_final(self):
        # _reuse_unchanged replaces an unchanged route's entry with the previous
        # one wholesale. Marking before it meant the counter was overwritten by
        # the very entry being carried forward, so it sat at its first value
        # forever and no route ever became offloadable — while the manifest
        # looked perfectly well-formed.
        source = (pathlib.Path(BACKEND) / "services" / "snapshot.py").read_text()
        body = source[source.index("def build_and_publish"):]
        body = body[:body.index("\ndef ", 1)]
        self.assertLess(body.index("_reuse_unchanged"), body.index("_mark_offloadable"),
                        "offload marking must run after the route set is final")


class StaticAssetTest(unittest.TestCase):
    """Assets are where the offloadable bytes are."""

    def module(self):
        return _load_pure("services/snapshot.py",
                          {"_asset_content_type", "_ASSET_TYPES",
                           "MAX_ASSET_BYTES", "MAX_ASSET_TOTAL_BYTES"})

    def test_content_types_are_explicit_not_guessed(self):
        # mimetypes guesses from system files that differ between the build host
        # and the container, and an asset served as the wrong type is a
        # stylesheet the browser refuses to apply.
        module = self.module()
        self.assertEqual(module["_asset_content_type"]("css/site.css"),
                         "text/css; charset=utf-8")
        self.assertEqual(module["_asset_content_type"]("js/app.js"),
                         "application/javascript; charset=utf-8")
        self.assertEqual(module["_asset_content_type"]("img/logo.png"), "image/png")

    def test_an_unknown_extension_does_not_masquerade_as_something(self):
        self.assertEqual(self.module()["_asset_content_type"]("odd.xyz"),
                         "application/octet-stream")

    def test_both_caps_exist(self):
        # A snapshot is fetched in full by every gateway, so one enormous file
        # would be paid for by all of them, repeatedly.
        module = self.module()
        self.assertGreater(module["MAX_ASSET_BYTES"], 0)
        self.assertGreater(module["MAX_ASSET_TOTAL_BYTES"], module["MAX_ASSET_BYTES"])

    def test_assets_go_through_the_same_stability_rule(self):
        # A deploy changes them, and a gateway serving last release's JavaScript
        # beside this release's HTML is a broken page. Trusting assets on sight
        # would hide that window rather than close it.
        source = (pathlib.Path(BACKEND) / "services" / "snapshot.py").read_text()
        body = source[source.index("def _add_static_assets"):]
        body = body[:body.index("\n_ASSET_TYPES")]
        self.assertIn('"source_hash": digest', body)
        self.assertNotIn('"offload": True', body,
                         "assets must earn offload through stability like anything else")
