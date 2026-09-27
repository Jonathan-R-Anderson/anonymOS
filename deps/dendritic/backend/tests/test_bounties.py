"""Escrow arithmetic, and the deadline that stops a bounty rotting.

The split is the part that has to be exactly right. An escrow holds one reward
and must divide it without inventing or losing a coin — a rounding rule that
favours the wrong side, or that lets the two payouts sum to more than was
escrowed, is the site quietly promising money it is not holding.
"""

import ast
import datetime
import os
import pathlib
import sys
import unittest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)


def _load_pure(relative_path, wanted, extra=None):
    source = (pathlib.Path(BACKEND) / relative_path).read_text()
    tree = ast.parse(source)
    keep = [node for node in tree.body
            if (isinstance(node, ast.Assign)
                and {t.id for t in node.targets if isinstance(t, ast.Name)} & wanted)
            or (isinstance(node, (ast.FunctionDef, ast.ClassDef))
                and node.name in wanted)]
    module = ast.Module(body=keep, type_ignores=[])
    ast.fix_missing_locations(module)
    namespace = dict(extra or {})
    exec(compile(module, relative_path, "exec"), namespace)
    return namespace


MODEL = _load_pure("model/Bounty.py",
                   {"REJECT_HUNTER_BPS", "MIN_REWARD", "REVIEW_DAYS", "trust_for"})
SERVICE = _load_pure(
    "services/bounties.py",
    {"BountyError", "reject_split", "validate_reward", "review_deadline",
     "review_overdue"},
    extra={"REJECT_HUNTER_BPS": MODEL["REJECT_HUNTER_BPS"],
           "MIN_REWARD": MODEL["MIN_REWARD"],
           "REVIEW_DAYS": MODEL["REVIEW_DAYS"],
           "SUBMISSION_PENDING": "pending",
           "datetime": datetime},
)


class _Submission:
    def __init__(self, status="pending", age_days=0):
        self.status = status
        self.created_at = datetime.datetime(2026, 1, 1) - datetime.timedelta(days=age_days)


class SplitTest(unittest.TestCase):
    def test_the_split_never_creates_or_loses_a_coin(self):
        # The escrow holds exactly `reward`. If these ever summed to more, the
        # site would owe money it is not holding.
        for reward in (20, 21, 33, 50, 99, 100, 101, 1_000, 999_999):
            hunter, poster = SERVICE["reject_split"](reward)
            self.assertEqual(hunter + poster, reward, reward)

    def test_neither_side_can_be_paid_a_negative_amount(self):
        for reward in (20, 37, 100, 12345):
            hunter, poster = SERVICE["reject_split"](reward)
            self.assertGreaterEqual(hunter, 0)
            self.assertGreaterEqual(poster, 0)

    def test_the_rejected_hunter_gets_the_advertised_slice(self):
        hunter, poster = SERVICE["reject_split"](100)
        self.assertEqual(hunter, 15)
        self.assertEqual(poster, 85)

    def test_the_remainder_goes_to_the_poster(self):
        # 33 * 15% = 4.95. Rounding it UP would pay out of an escrow that does
        # not have it; the fraction is kept by the side being refunded.
        hunter, poster = SERVICE["reject_split"](33)
        self.assertEqual(hunter, 4)
        self.assertEqual(poster, 29)

    def test_rejecting_always_costs_the_poster_something(self):
        # The whole mechanism. If a rejection were free, reading a report and
        # saying no would be strictly better than paying for it.
        for reward in range(MODEL["MIN_REWARD"], MODEL["MIN_REWARD"] + 50):
            hunter, _ = SERVICE["reject_split"](reward)
            self.assertGreater(hunter, 0, reward)

    def test_accepting_is_cheaper_for_the_hunter_than_being_rejected(self):
        hunter, _ = SERVICE["reject_split"](100)
        self.assertLess(hunter, 100)


class RewardTest(unittest.TestCase):
    def test_a_reward_below_the_floor_is_refused(self):
        # Below MIN_REWARD the hunter's slice rounds to zero and the protection
        # disappears silently, which is worse than refusing the bounty.
        with self.assertRaises(SERVICE["BountyError"]):
            SERVICE["validate_reward"](MODEL["MIN_REWARD"] - 1)

    def test_the_floor_itself_still_pays_a_slice(self):
        reward = SERVICE["validate_reward"](MODEL["MIN_REWARD"])
        hunter, _ = SERVICE["reject_split"](reward)
        self.assertGreater(hunter, 0)

    def test_nonsense_is_refused_rather_than_defaulted(self):
        for bad in ("", "lots", None, "12.5"):
            with self.assertRaises(SERVICE["BountyError"]):
                SERVICE["validate_reward"](bad)

    def test_a_negative_reward_is_refused(self):
        with self.assertRaises(SERVICE["BountyError"]):
            SERVICE["validate_reward"](-100)


class DeadlineTest(unittest.TestCase):
    """A poster who never answers is the commonest way an escrow rots."""

    def test_a_fresh_submission_is_not_overdue(self):
        self.assertFalse(SERVICE["review_overdue"](
            _Submission(age_days=0), now=datetime.datetime(2026, 1, 1)))

    def test_the_window_closes_after_the_review_period(self):
        overdue = SERVICE["review_overdue"](
            _Submission(age_days=MODEL["REVIEW_DAYS"] + 1),
            now=datetime.datetime(2026, 1, 1))
        self.assertTrue(overdue)

    def test_an_answered_submission_has_no_deadline(self):
        # Escalating something already resolved is not a thing.
        self.assertIsNone(SERVICE["review_deadline"](_Submission(status="accepted")))
        self.assertFalse(SERVICE["review_overdue"](_Submission(status="rejected")))

    def test_no_submission_means_no_deadline(self):
        self.assertIsNone(SERVICE["review_deadline"](None))
        self.assertFalse(SERVICE["review_overdue"](None))


if __name__ == "__main__":
    unittest.main()
