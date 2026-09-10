"""What survives when an account goes, and what a slug may claim.

Three defects an adversarial review found in code that had 1715 passing tests.
None of them was reachable from the existing suite, so each gets a test that
would have failed before the fix.
"""

import ast
import os
import sys
import types
import unittest
from unittest.mock import MagicMock

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)


def _install_stubs():
    if "shared" not in sys.modules:
        shared = types.ModuleType("shared")
        db = MagicMock()
        db.Model = object
        shared.db = db
        shared.app = MagicMock()
        shared.app.config = {}
        sys.modules["shared"] = shared


_install_stubs()


def _column_kwargs(module_file, class_name, column):
    """The keyword arguments a model declares for one column, read from source.

    Read from the declaration rather than the imported class because whichever
    test module imports first decides what `shared` is, and under a MagicMock
    every column is an anonymous mock with no arguments to inspect.
    """
    tree = ast.parse(open(os.path.join(BACKEND, module_file), encoding="utf-8").read())
    for node in ast.walk(tree):
        if not (isinstance(node, ast.ClassDef) and node.name == class_name):
            continue
        for statement in node.body:
            if not isinstance(statement, ast.Assign):
                continue
            for target in statement.targets:
                if not (isinstance(target, ast.Name) and target.id == column):
                    continue
                call = statement.value
                if not isinstance(call, ast.Call):
                    return {}
                return {kw.arg: getattr(kw.value, "value", kw.value)
                        for kw in call.keywords}
    return None


class PublishedWorkOutlivesTheAccountTest(unittest.TestCase):
    """Invariant 7: a retraction leaves the URL live, never a 404.

    `blueprints/admin._delete_slip` deletes every row whose slip_id is NOT
    NULL, on the reasoning that such a row cannot exist without the account.
    That is right for a vote and wrong for a story: NewsStory.slip_id was NOT
    NULL *by design*, so deleting an author destroyed their published,
    corrected and retracted stories -- URLs already in other people's citations,
    and the retraction notices an editor wrote about them.
    """

    def test_the_author_column_is_nullable_so_the_row_can_survive(self):
        kwargs = _column_kwargs("model/NewsStory.py", "NewsStory", "slip_id")
        self.assertIsNotNone(kwargs, "slip_id declaration not found")
        self.assertIs(kwargs.get("nullable"), True,
                      "a NOT NULL slip_id makes _delete_slip destroy published "
                      "stories rather than release them")

    def test_the_pen_name_owner_is_nullable_for_the_same_reason(self):
        kwargs = _column_kwargs("model/PenName.py", "PenName", "owner_slip_id")
        self.assertIs(kwargs.get("nullable"), True)

    def test_deletion_releases_public_work_and_removes_only_drafts(self):
        source = open(os.path.join(BACKEND, "blueprints", "admin.py"),
                      encoding="utf-8").read()
        helper = source[source.index("def _release_published_work"):
                        source.index("def _delete_slip")]
        # Public statuses are UPDATEd to a null author, not deleted.
        self.assertIn("PUBLIC_STATUSES", helper)
        self.assertIn("NewsStory.slip_id: None", helper)
        # Unpublished work, which has no public URL, does go.
        self.assertIn("~NewsStory.status.in_(PUBLIC_STATUSES)", helper)

    def test_the_release_runs_before_the_generic_cascade(self):
        """Ordering is the whole fix. The generic loop deletes any row with a
        non-nullable slip_id, so releasing afterwards would release nothing."""
        source = open(os.path.join(BACKEND, "blueprints", "admin.py"),
                      encoding="utf-8").read()
        body = source[source.index("def _delete_slip"):]
        body = body[:body.index("@admin_blueprint.route")]
        self.assertLess(body.index("_release_published_work"),
                        body.index("for table, column in reversed"))

    def test_a_pen_name_is_retired_rather_than_deleted(self):
        """Retirement is what stops a released slug being reissued. A deleted
        row would free the name for somebody who inherits its readers."""
        source = open(os.path.join(BACKEND, "blueprints", "admin.py"),
                      encoding="utf-8").read()
        helper = source[source.index("def _release_published_work"):
                        source.index("def _delete_slip")]
        self.assertIn("PenName.retired: True", helper)
        self.assertNotIn("PenName).filter(PenName.owner_slip_id == slip_id).delete",
                         helper)


class SlugNamespaceTest(unittest.TestCase):
    """Author pages share one URL space, so both sides must check both tables."""

    def _profile_edit_source(self):
        source = open(os.path.join(BACKEND, "blueprints", "profiles.py"),
                      encoding="utf-8").read()
        start = source.index("def edit(")
        return source[start:source.index("def delete(")]

    def test_profile_edit_refuses_a_slug_a_pen_name_holds(self):
        body = self._profile_edit_source()
        self.assertIn("PenName.slug == slug", body,
                      "profiles.edit checked only the Profile table, so an "
                      "account could capture a published pen name's slug")

    def test_pen_name_creation_still_checks_both(self):
        source = open(os.path.join(BACKEND, "model", "PenName.py"),
                      encoding="utf-8").read()
        checker = source[source.index("def slug_is_available"):
                         source.index("class PenName")]
        self.assertIn("Profile.slug == slug", checker)
        self.assertIn("PenName.slug == slug", checker)

    def test_a_retired_pen_name_still_holds_its_slug_on_both_sides(self):
        """A released name is never reissued -- neither to another pen name nor
        to a profile."""
        pen_source = open(os.path.join(BACKEND, "model", "PenName.py"),
                          encoding="utf-8").read()
        checker = pen_source[pen_source.index("def slug_is_available"):
                             pen_source.index("class PenName")]
        self.assertNotIn("retired", checker,
                         "filtering out retired names would reissue them")
        self.assertNotIn("retired", self._profile_edit_source()
                         [self._profile_edit_source().index("PenName.slug == slug"):
                          self._profile_edit_source().index("PenName.slug == slug") + 300])


class ByLineIsPartOfWhatWasApprovedTest(unittest.TestCase):
    """content_hash covers the text; the byline sat outside it."""

    def _save_draft(self):
        source = open(os.path.join(BACKEND, "services", "newsroom.py"),
                      encoding="utf-8").read()
        return source[source.index("def save_draft"):source.index("def _normalise_tags")]

    def test_changing_the_byline_invalidates_the_approval(self):
        body = self._save_draft()
        self.assertIn("byline_changed", body)
        self.assertIn("content_changed or byline_changed", body)

    def test_the_pen_name_is_revalidated_at_publish(self):
        """Review takes days. A name retired in between must not ship."""
        source = open(os.path.join(BACKEND, "services", "newsroom.py"),
                      encoding="utf-8").read()
        publish = source[source.index("def publish_story"):source.index("def correct_story")]
        self.assertIn("usable", publish)
        self.assertIn("BYLINE_PEN_NAME", publish)


# These tests read files removed with the stripped features: blueprints/news_editor.py.
#
# SKIPPED CONDITIONALLY RATHER THAN DELETED, matching the civil-rights
# classes in test_evidence_upload.py. The assertions are still correct and
# worth keeping; a skipUnless brings them back the moment the files exist
# again, which a deletion cannot do. PER METHOD, not per class: these
# classes are MIXED, and skipping a whole one destroys its working tests.
_NEWS_EDITOR_PRESENT = all(
    os.path.exists(os.path.join(BACKEND, part)) for part in (
        "blueprints/news_editor.py",
    )
)
_NEWS_EDITOR_PRESENT_GONE = "the news-editor blueprint was removed; this reads it"

class CsrfTest(unittest.TestCase):
    """Ten editor routes rendered a token and checked none of them."""

    @unittest.skipUnless(_NEWS_EDITOR_PRESENT, _NEWS_EDITOR_PRESENT_GONE)
    def test_every_editor_post_route_is_csrf_protected(self):
        source = open(os.path.join(BACKEND, "blueprints", "news_editor.py"),
                      encoding="utf-8").read()
        tree = ast.parse(source)
        unprotected = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            names, is_post = set(), False
            for dec in node.decorator_list:
                if isinstance(dec, ast.Name):
                    names.add(dec.id)
                elif isinstance(dec, ast.Call):
                    func = dec.func
                    if isinstance(func, ast.Attribute) and func.attr == "route":
                        for kw in dec.keywords or []:
                            if kw.arg == "methods":
                                values = [getattr(e, "value", None)
                                          for e in getattr(kw.value, "elts", [])]
                                is_post = "POST" in values
                    elif isinstance(func, ast.Name):
                        names.add(func.id)
            if is_post and "csrf_protect" not in names:
                unprotected.append(node.name)
        self.assertEqual(unprotected, [],
                         "unprotected state-changing routes: %s" % unprotected)


if __name__ == "__main__":
    unittest.main()
