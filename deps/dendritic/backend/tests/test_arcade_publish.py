"""Publishing the arcade to the DHT.

The bug this guards against is not a crash — it is a publisher that quietly
republishes everything on every sweep, or quietly publishes nothing. Both look
identical from outside, which is how the codeplay publisher managed to exist for
months with 267 rows of content and zero snapshots on the network.
"""

import hashlib
import json
import os
import pathlib
import sys
import types
import unittest

BACKEND = pathlib.Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))


def _import_with_stubbed_shared():
    """Import arcade_publish against a fake `shared`, then put sys.modules back.

    The module needs `shared` at import time, and `shared` needs the whole app
    and a database. Stubbing it lets the pure document-building half be tested
    without either — that half decides what lands on the network, so it is worth
    testing.

    The RESTORE is the part that matters. An earlier version left the stub in
    sys.modules, and because pytest collects this file early, four unrelated
    test modules then imported the fake and died on it. A test that breaks other
    tests is worse than the one it was guarding.
    """
    stub = types.ModuleType("shared")

    class _Logger:
        def info(self, *a, **k): pass
        def exception(self, *a, **k): pass
        def warning(self, *a, **k): pass

    # `db` needs enough shape for model modules to be IMPORTED — publish()
    # imports SiteSetting, which subclasses db.Model at module level. Nothing
    # here queries; the stub only has to survive the import.
    class _Model:
        pass

    stub.app = types.SimpleNamespace(config={}, logger=_Logger())
    stub.db = types.SimpleNamespace(
        session=None, Model=_Model,
        Column=lambda *a, **k: None, Integer=None, String=lambda *a, **k: None,
        Text=None, DateTime=None, Boolean=None,
    )
    previous = sys.modules.get("shared")
    sys.modules["shared"] = stub
    try:
        import importlib
        return importlib.import_module("services.arcade_publish")
    finally:
        if previous is not None:
            sys.modules["shared"] = previous
        else:
            sys.modules.pop("shared", None)


arcade_publish = _import_with_stubbed_shared()


class DocumentTest(unittest.TestCase):
    def setUp(self):
        self.docs = arcade_publish._documents()
        self.by_key = dict(self.docs)

    def test_every_course_is_published(self):
        from services import school as course
        for subject in course.subjects():
            self.assertIn("school/%s.json" % subject["slug"], self.by_key,
                          "%s would never reach the network" % subject["slug"])

    def test_the_vocabulary_is_published(self):
        self.assertIn("vocabulary.json", self.by_key)
        payload = json.loads(self.by_key["vocabulary.json"])
        from services import vocab as glossary
        self.assertEqual(len(payload["terms"]), len(glossary.all_terms()))

    def test_courses_carry_their_chapters_not_just_a_title(self):
        # A published index of titles would look successful and be worthless.
        payload = json.loads(self.by_key["school/crypto.json"])
        chapters = sum(len(part["chapters"]) for part in payload["parts"])
        self.assertGreater(chapters, 50)
        self.assertTrue(payload["parts"][0]["chapters"][0]["body"].strip())

    def test_the_index_names_everything_else(self):
        # So a reader fetching one object learns what exists without listing.
        index = json.loads(self.by_key["index.json"])
        keys = {entry["key"] for entry in index["school"]}
        for key in self.by_key:
            if key.startswith("school/"):
                self.assertIn(key, keys)
        self.assertEqual(index["vocabulary"]["key"], "vocabulary.json")

    def test_index_digests_match_the_documents(self):
        index = json.loads(self.by_key["index.json"])
        for entry in index["school"]:
            body = self.by_key[entry["key"]]
            self.assertEqual(entry["sha256"], hashlib.sha256(body).hexdigest())

    def test_serialisation_is_stable(self):
        # THE important one. Unstable bytes mean a different digest every sweep,
        # so nothing is ever "unchanged" and the publisher re-uploads every
        # document hourly, forever.
        first = {k: hashlib.sha256(v).hexdigest() for k, v in arcade_publish._documents()}
        second = {k: hashlib.sha256(v).hexdigest() for k, v in arcade_publish._documents()}
        self.assertEqual(first, second)

    def test_documents_are_valid_utf8_json(self):
        for key, body in self.docs:
            json.loads(body.decode("utf-8"))


class SafetyTest(unittest.TestCase):
    def test_publishing_without_a_gateway_is_a_no_op_not_a_crash(self):
        # It runs on a timer in every environment, including ones with no DHT
        # configured. Raising there would fill the log hourly.
        original = arcade_publish._client
        arcade_publish._client = lambda: None
        try:
            self.assertEqual(arcade_publish.publish(), {})
        finally:
            arcade_publish._client = original

    def test_this_module_never_deletes_anything(self):
        # The node bridge exposes PUT on /dcs/blob and no GET, so nothing here
        # can read a published object back to confirm it survived. Deleting a
        # local copy on the strength of an unverified put would trade a copy we
        # can check for one we cannot.
        source = (BACKEND / "services" / "arcade_publish.py").read_text()
        for forbidden in ("delete_object", "db.session.delete", "DROP ", "truncate"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
