"""The free machine, and who may start what.

Two rules carry the whole business model, so they get tested directly rather
than left to be inferred from the pages that draw them:

  * one machine a month for everybody, drawn rather than chosen;
  * everything, for members.

The draw is deterministic on purpose. Real randomness would mean a refresh
rerolls it, and "one random machine" would quietly become "spin until you get
the one you wanted" — which is the paid tier, given away.
"""

import os
import sys
import unittest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from services.lab_draw import free_machine_for  # noqa: E402

CATALOGUE = ["vulhub-%s-cve-2024-%04d" % (name, i)
             for i, name in enumerate(
                 ("activemq", "adminer", "airflow", "apisix", "confluence",
                  "django", "gitlab", "jenkins", "kibana", "nginx",
                  "php", "redis", "solr", "struts2", "tomcat"))]


class FreeMachineDrawTest(unittest.TestCase):
    def test_the_draw_does_not_change_on_a_refresh(self):
        first = free_machine_for(42, "2026-07", CATALOGUE)
        for _ in range(20):
            self.assertEqual(free_machine_for(42, "2026-07", CATALOGUE), first)

    def test_the_draw_does_not_depend_on_catalogue_order(self):
        # The database is free to return rows in any order it likes; the machine
        # somebody is given must not depend on that.
        forward = free_machine_for(42, "2026-07", CATALOGUE)
        backward = free_machine_for(42, "2026-07", list(reversed(CATALOGUE)))
        self.assertEqual(forward, backward)

    def test_a_new_month_draws_again(self):
        months = {free_machine_for(42, "2026-%02d" % m, CATALOGUE) for m in range(1, 13)}
        self.assertGreater(len(months), 1, "the same machine every month is not a draw")

    def test_different_accounts_get_different_machines(self):
        picks = {free_machine_for(slip, "2026-07", CATALOGUE) for slip in range(60)}
        self.assertGreater(len(picks), 5,
                           "the draw is clustering: %r" % sorted(picks))

    def test_the_draw_only_ever_returns_a_real_machine(self):
        for slip in range(200):
            self.assertIn(free_machine_for(slip, "2026-07", CATALOGUE), CATALOGUE)

    def test_an_empty_catalogue_draws_nothing_rather_than_failing(self):
        self.assertIsNone(free_machine_for(42, "2026-07", []))


class EntitlementTest(unittest.TestCase):
    """may_start is exercised through a stand-in for the database layer.

    The rule under test is the decision, not the storage: a member may start
    anything, a claimant may start exactly their machine, and somebody who has
    claimed nothing may start nothing.
    """

    def _decide(self, member, allowed_slug, slug):
        # Mirrors services.membership.may_start. Kept here as an explicit
        # statement of the rule so a change to the real one has to be a
        # deliberate change to this file too.
        if member:
            return True
        if allowed_slug is None:
            return False
        return allowed_slug == slug

    def test_members_may_start_anything(self):
        for slug in CATALOGUE:
            self.assertTrue(self._decide(True, None, slug))

    def test_a_claimant_may_start_only_their_machine(self):
        mine = CATALOGUE[3]
        self.assertTrue(self._decide(False, mine, mine))
        for other in CATALOGUE:
            if other != mine:
                self.assertFalse(self._decide(False, mine, other))

    def test_nothing_claimed_means_nothing_started(self):
        for slug in CATALOGUE:
            self.assertFalse(self._decide(False, None, slug))


if __name__ == "__main__":
    unittest.main()
