"""What the site does with the two answers a relay can give.

The dispatcher treats "the node declined" and "the node never answered" as
different facts: a refusal leaves the job QUEUED and surfaces a reason, while
unreachability moves on. Carrying compute over the peer protocol put a relay in
between, and a relay is exactly where those two collapse into one if nobody is
watching — a failed dial arrives as a 5xx, and a 5xx already means "declined".

So these tests are almost entirely about that one distinction, plus the shape of
what goes on the wire, because a target derived from configuration instead of
from the node's own heartbeat is the failure this module was written to avoid.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from services import compute_bridge  # noqa: E402


class FakeResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        if isinstance(self._payload, str):
            raise ValueError("not json")
        return self._payload


class FakeRequests:
    """Stands in for the `requests` module inside compute_bridge.

    A whole stand-in rather than a patched `requests.post`, because that
    attribute is shared with every other module in the process — a test that
    failed to put it back would break things that have nothing to do with
    compute.
    """

    RequestException = __import__("requests").RequestException

    def __init__(self):
        self.posts = []
        self._answer = None

    def post(self, url, json=None, timeout=None, **kwargs):
        self.posts.append((url, json, kwargs))
        if isinstance(self._answer, Exception):
            raise self._answer
        return self._answer


class BridgeTestCase(unittest.TestCase):
    """A site with a node bridged to it, and a fake relay at the end of it."""

    NODE = {"id": "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN",
            "i2p_destination": "a" * 52}

    def setUp(self):
        self._saved = {name: os.environ.get(name)
                       for name in ("COMPUTE_NODE_BRIDGE", "DCS_NODE_URL")}
        os.environ["COMPUTE_NODE_BRIDGE"] = "http://node.local:8760"
        os.environ["DCS_NODE_URL"] = ""
        self._real_requests = compute_bridge.requests
        self.http = FakeRequests()
        compute_bridge.requests = self.http
        self.addCleanup(self._restore)

    @property
    def posts(self):
        return self.http.posts

    def _restore(self):
        compute_bridge.requests = self._real_requests
        for name, value in self._saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    def relay(self, status_code, payload):
        """Point the bridge at a relay that always answers this."""
        self.http._answer = FakeResponse(status_code, payload)

    def relay_raises(self, exc):
        self.http._answer = exc


class TransportTest(BridgeTestCase):
    """Where the work goes, and how it is addressed."""

    def test_enabled_follows_the_bridged_node_not_a_proxy(self):
        self.assertTrue(compute_bridge.enabled())
        os.environ["COMPUTE_NODE_BRIDGE"] = ""
        self.assertFalse(compute_bridge.enabled())

    def test_the_target_comes_from_the_nodes_own_heartbeat(self):
        # The reason this module refuses a configured address: the peer and the
        # destination are both what the NODE said about itself, so dispatch
        # follows placement rather than a name in a config file.
        target = compute_bridge.endpoint_for(self.NODE)
        self.assertEqual(target["peer"], self.NODE["id"])
        self.assertEqual(target["destination"], self.NODE["i2p_destination"])

    def test_a_node_that_named_no_identity_is_not_dispatched_to(self):
        self.assertIsNone(compute_bridge.endpoint_for({"i2p_destination": "a" * 52}))
        self.assertIsNone(compute_bridge.endpoint_for({}))
        self.assertIsNone(compute_bridge.endpoint_for(None))

    def test_the_job_is_relayed_to_the_named_peer_through_our_own_node(self):
        self.relay(200, {"admitted": True})
        compute_bridge.admit(self.NODE, "cpu")
        url, body, _ = self.posts[0]
        # Our node, not the volunteer: the volunteer has no address this site
        # could ever post to.
        self.assertEqual(url, "http://node.local:8760/compute/peer/admit")
        self.assertEqual(body["peer"], self.NODE["id"])
        self.assertEqual(body["destination"], self.NODE["i2p_destination"])
        # The job itself is nested and forwarded whole, so a field this site
        # adds later still reaches a node through an older relay.
        self.assertEqual(body["request"], {"device": "cpu"})

    def test_no_bridged_node_is_unavailable_not_a_refusal(self):
        os.environ["COMPUTE_NODE_BRIDGE"] = ""
        with self.assertRaises(compute_bridge.BridgeUnavailable):
            compute_bridge.admit(self.NODE, "cpu")

    def test_our_own_node_not_answering_is_unavailable(self):
        self.relay_raises(self.http.RequestException("connection refused"))
        with self.assertRaises(compute_bridge.BridgeUnavailable):
            compute_bridge.admit(self.NODE, "cpu")


class RefusalTest(BridgeTestCase):
    """A node that declined has ANSWERED. It must not read as a failure."""

    def test_a_busy_node_is_a_retryable_refusal(self):
        self.relay(503, {"admitted": False, "reason": "the machine is warm",
                         "retryable": True})
        with self.assertRaises(compute_bridge.Refused) as caught:
            compute_bridge.admit(self.NODE, "cpu")
        self.assertIn("warm", caught.exception.reason)
        self.assertTrue(caught.exception.retryable)

    def test_an_unknown_workload_is_a_permanent_refusal(self):
        # A 4xx is our request being wrong. Asking again with the same payload
        # gets the same answer, so it must not be retried for ever.
        self.relay(400, {"error": "unsupported workload: nonsense"})
        with self.assertRaises(compute_bridge.Refused) as caught:
            compute_bridge.submit(self.NODE, 11, "cpu", "python", "main.py", {},
                                  workload="nonsense")
        self.assertFalse(caught.exception.retryable)

    def test_a_node_that_declined_is_not_reported_as_unreachable(self):
        # THE DISTINCTION, stated as its own test. A refusal reaching the caller
        # as BridgeUnavailable would lose the node's reason and, worse, look like
        # the network is down when one volunteer's laptop was simply busy.
        self.relay(503, {"admitted": False, "reason": "no GPU offered",
                         "retryable": False})
        with self.assertRaises(compute_bridge.Refused):
            compute_bridge.admit(self.NODE, "gpu:cuda")

    def test_a_refused_submit_is_not_mistaken_for_an_accepted_one(self):
        self.relay(200, {"accepted": False, "reason": "no free slot",
                         "retryable": True})
        with self.assertRaises(compute_bridge.Refused) as caught:
            compute_bridge.submit(self.NODE, 11, "cpu", "python", "main.py",
                                  {"main.py": "print(1)"})
        self.assertTrue(caught.exception.retryable)


class UnreachableTest(BridgeTestCase):
    """A peer nobody could reach has NOT answered."""

    def test_an_unreachable_peer_is_unavailable_not_a_refusal(self):
        # THE TRAP this marker exists for. The relay reports a failed dial with
        # a 5xx, and 5xx already means "the node declined" here — so without the
        # `unreachable` flag being read FIRST, every volunteer whose router was
        # down would be recorded as having considered the job and said no.
        self.relay(504, {"unreachable": True,
                         "error": "could not reach 12D3Koo... over the peer network: all dials failed"})
        with self.assertRaises(compute_bridge.BridgeUnavailable) as caught:
            compute_bridge.admit(self.NODE, "cpu")
        self.assertIn("all dials failed", str(caught.exception))

    def test_an_unreachable_peer_on_submit_is_also_unavailable(self):
        self.relay(504, {"unreachable": True, "error": "all dials failed"})
        with self.assertRaises(compute_bridge.BridgeUnavailable):
            compute_bridge.submit(self.NODE, 11, "cpu", "python", "main.py",
                                  {"main.py": "print(1)"})

    def test_an_unreachable_peer_on_result_is_also_unavailable(self):
        self.relay(504, {"unreachable": True, "error": "all dials failed"})
        with self.assertRaises(compute_bridge.BridgeUnavailable):
            compute_bridge.result(self.NODE, 11)

    def test_a_non_json_answer_is_unavailable(self):
        self.relay(200, "<html>proxy error</html>")
        with self.assertRaises(compute_bridge.BridgeUnavailable):
            compute_bridge.admit(self.NODE, "cpu")


class ResultTest(BridgeTestCase):
    """Polling, which has a third state neither of the above covers."""

    def test_a_running_job_returns_none_rather_than_raising(self):
        self.relay(200, {"done": False, "running": True})
        self.assertIsNone(compute_bridge.result(self.NODE, 11))

    def test_a_finished_job_comes_back_whole(self):
        # Outputs are the PRODUCT of a workload run; a caller that picked out
        # stdout would throw away the only thing the job was submitted for.
        self.relay(200, {"done": True, "result": {
            "exit_code": 0, "stdout": "embed-digest sha256:abc",
            "outputs": {"output.jsonl": "{}"}, "output_truncated": False}})
        result = compute_bridge.result(self.NODE, 11)
        self.assertEqual(result["outputs"], {"output.jsonl": "{}"})

    def test_a_job_the_node_has_never_heard_of_is_unavailable(self):
        # Distinguished from "still running" so the caller can requeue instead
        # of polling something that will never finish.
        self.relay(404, {"done": False, "error": "unknown job"})
        with self.assertRaises(compute_bridge.BridgeUnavailable):
            compute_bridge.result(self.NODE, 11)


class PayloadTest(BridgeTestCase):
    """What a submit actually carries."""

    def test_the_isolation_flag_travels_with_the_job(self):
        # Placement routes an arbitrary job to a node reporting microVM
        # isolation; if the request does not SAY so the node reads it as an
        # ordinary catalogue job and runs it in a container.
        self.relay(200, {"accepted": True, "ticket": "t"})
        compute_bridge.submit(self.NODE, 11, "cpu", "python", "main.py",
                              {"main.py": "print(1)"}, arbitrary=True)
        request = self.posts[0][1]["request"]
        self.assertTrue(request["arbitrary"])
        # Always present, including false: absent and false must not be the same
        # wire state.
        self.relay(200, {"accepted": True, "ticket": "t"})
        compute_bridge.submit(self.NODE, 12, "cpu", "python", "main.py",
                              {"main.py": "print(1)"})
        self.assertIn("arbitrary", self.posts[1][1]["request"])
        self.assertFalse(self.posts[1][1]["request"]["arbitrary"])

    def test_a_workload_carries_its_seed_and_params(self):
        self.relay(200, {"accepted": True, "ticket": "sha256:unit"})
        ticket = compute_bridge.submit(self.NODE, 11, "cpu", "python", "", {},
                                       workload="embed",
                                       params={"model": "minilm"}, seed=7)
        request = self.posts[0][1]["request"]
        self.assertEqual(request["workload"], "embed")
        self.assertEqual(request["params"], {"model": "minilm"})
        self.assertEqual(request["seed"], 7)
        self.assertEqual(ticket, "sha256:unit")

    def test_the_relay_body_is_json_serialisable(self):
        # It is posted with json=, so anything unserialisable here fails at
        # dispatch on a live node and nowhere earlier.
        self.relay(200, {"accepted": True, "ticket": "t"})
        compute_bridge.submit(self.NODE, 11, "cpu", "python", "main.py",
                              {"main.py": "print(1)"}, stdin="x",
                              timeout_seconds=300)
        json.dumps(self.posts[0][1])


if __name__ == "__main__":
    unittest.main()
