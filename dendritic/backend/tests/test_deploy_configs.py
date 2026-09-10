"""The greeting file exists twice, and both copies are live.

`DEFAULT_GREETING_PATH` is the RELATIVE path "deploy-configs/index-greeting.html",
so which file it opens depends on the working directory:

  * in the container, WORKDIR is /maniwani and the Dockerfile copies the
    REPO-ROOT `deploy-configs/` there — so production reads the root copy;
  * running the app locally, the working directory is `backend/`, so it reads
    `backend/deploy-configs/`.

Neither is wrong and neither is unused, which is exactly what makes this
dangerous: an edit to one is invisible in the other environment, with no error
anywhere. That already happened — the front page was edited three times, tested,
committed and deployed, and production kept serving the old page because every
edit went to the copy the image does not ship.

So this test asserts they are identical. It is the only mechanism that notices;
a person comparing two files in different directories notices once and then
stops.
"""

import os
import pathlib
import unittest

BACKEND = pathlib.Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REPO = BACKEND.parent

RELATIVE = pathlib.Path("deploy-configs") / "index-greeting.html"


class GreetingCopiesTest(unittest.TestCase):
    def test_both_copies_exist(self):
        for base in (REPO, BACKEND):
            with self.subTest(base=base.name):
                self.assertTrue((base / RELATIVE).is_file(),
                                "%s is missing" % (base / RELATIVE))

    def test_the_copies_are_identical(self):
        """Whichever one somebody edits, production must get that edit.

        If this fails, copy the newer file over the older one. Do not "fix" it
        by deleting a copy: the container reads the root one and a local run
        reads the backend one, so removing either breaks that environment
        silently rather than loudly.
        """
        root = (REPO / RELATIVE).read_text()
        backend = (BACKEND / RELATIVE).read_text()
        if root == backend:
            return
        self.fail(
            "deploy-configs/index-greeting.html has drifted between the repo "
            "root (%d chars, what the image ships) and backend/ (%d chars, what "
            "a local run reads). Production serves the ROOT copy." % (
                len(root), len(backend)))

    def test_the_shipped_copy_links_the_network_page(self):
        """The front-page graph is the entrance to /network.

        Asserted against the ROOT copy specifically, because that is the file
        the container serves and the one whose absence of a link was invisible
        for three deploys.
        """
        shipped = (REPO / RELATIVE).read_text()
        self.assertIn('href="/network"', shipped)


if __name__ == "__main__":
    unittest.main()
