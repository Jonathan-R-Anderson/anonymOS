"""Verification: running a job twice and comparing.

The comparison rules are loaded standalone, so what decides whether a node gets
paid can be tested without a database.
"""

import importlib.util
import os
import sys
import unittest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)


def load():
    spec = importlib.util.spec_from_file_location(
        "verify_under_test", os.path.join(BACKEND, "services", "compute_verify.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def ok(stdout, code=0, stderr=""):
    return {"stdout": stdout, "exit_code": code, "stderr": stderr}


class CompareTest(unittest.TestCase):
    def setUp(self):
        self.v = load()

    def test_two_independent_nodes_agreeing_is_verified(self):
        verdict, digest, nodes = self.v.compare([("a", ok("42\n")), ("b", ok("42\n"))])
        self.assertEqual(verdict, self.v.VERDICT_AGREED)
        self.assertTrue(digest)
        self.assertEqual(nodes, ["a", "b"])

    # THE check that makes a quorum mean anything. Two results from one node are
    # one result counted twice, and accepting them would pass exactly when a
    # single dishonest node ran the job twice.
    def test_one_node_cannot_agree_with_itself(self):
        verdict, _, _ = self.v.compare([("a", ok("42\n")), ("a", ok("42\n"))])
        self.assertEqual(verdict, self.v.VERDICT_INSUFFICIENT)

    def test_disagreement_does_not_name_a_culprit(self):
        # Two nodes, two answers. Somebody is wrong; the comparison cannot say
        # who, and claiming otherwise would punish an honest node half the time.
        verdict, digest, nodes = self.v.compare([("a", ok("42\n")), ("b", ok("43\n"))])
        self.assertEqual(verdict, self.v.VERDICT_DISAGREED)
        self.assertIsNone(digest)
        self.assertEqual(nodes, [])

    def test_a_majority_wins_when_one_node_lies(self):
        verdict, _, nodes = self.v.compare([
            ("a", ok("42\n")), ("b", ok("42\n")), ("liar", ok("99\n"))])
        self.assertEqual(verdict, self.v.VERDICT_AGREED)
        self.assertEqual(nodes, ["a", "b"])

    def test_stderr_does_not_affect_the_verdict(self):
        # Warnings, timings and paths differ between honest runs. Including
        # stderr would report two identical computations as a disagreement
        # because one node's compiler was chattier.
        verdict, _, _ = self.v.compare([
            ("a", ok("42\n", stderr="warning: unused variable")),
            ("b", ok("42\n", stderr="")),
        ])
        self.assertEqual(verdict, self.v.VERDICT_AGREED)

    def test_exit_code_is_part_of_the_result(self):
        # Same output, different exit code is a different outcome — a program
        # that printed its answer and then crashed did not succeed.
        verdict, _, _ = self.v.compare([("a", ok("42\n", 0)), ("b", ok("42\n", 1))])
        self.assertEqual(verdict, self.v.VERDICT_DISAGREED)

    def test_no_results_is_insufficient_not_agreed(self):
        self.assertEqual(self.v.compare([])[0], self.v.VERDICT_INSUFFICIENT)


class PolicyTest(unittest.TestCase):
    def setUp(self):
        self.v = load()

    def test_gpu_work_is_not_verifiable_by_comparison(self):
        # Two honest cards disagree by construction. Reporting that as fraud
        # would punish nodes for doing exactly what was asked.
        class Job:
            device = "gpu:cuda"
        self.assertFalse(self.v.is_verifiable(Job()))

        class CPUJob:
            device = "cpu"
        self.assertTrue(self.v.is_verifiable(CPUJob()))

    def test_sampling_is_reproducible_so_a_dispute_can_be_checked(self):
        # A node that lost payment over a failed verification must be able to
        # see the job really was selected.
        first = [self.v.should_verify("job-%d" % i) for i in range(50)]
        again = [self.v.should_verify("job-%d" % i) for i in range(50)]
        self.assertEqual(first, again)

    def test_sampling_actually_samples(self):
        picked = sum(self.v.should_verify("job-%d" % i, rate=0.25) for i in range(400))
        # Not all, not none — the point is that a node cannot predict which.
        self.assertGreater(picked, 20)
        self.assertLess(picked, 380)

    def test_rate_extremes_are_honoured(self):
        self.assertTrue(all(self.v.should_verify("j%d" % i, rate=1.0) for i in range(20)))
        self.assertFalse(any(self.v.should_verify("j%d" % i, rate=0.0) for i in range(20)))


if __name__ == "__main__":
    unittest.main()
