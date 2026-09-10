"""Publishing where a joining node can find the network.

This writes to a live DNS zone, so the tests are mostly about what it must
refuse to do. The failure that matters is not "a record is missing" — it is
"the record set was emptied", which leaves a name that answers with nothing and
a joining node with nowhere to go.
"""

from __future__ import annotations

import asyncio

import pytest

from backend.srv import (DEFAULTS, SERVICE_LABEL, Desired, desired_records,
                         plan, reconcile, target_of)


def existing(*targets, start_id=1):
    # Name.com's real shape: weight, port and target packed into `answer`, with
    # only priority as a field of its own. Confirmed by asking the API.
    return [{"id": start_id + i, "type": "SRV", "host": SERVICE_LABEL,
             "answer": "10 443 %s" % t, "priority": 10}
            for i, t in enumerate(targets)]


class TestDesired:
    def test_it_is_stable_for_the_same_input(self):
        """An unstable plan churns records every reconcile for no reason."""
        a = desired_records(["gw-b.x.org", "gw-a.x.org"])
        b = desired_records(["gw-a.x.org", "gw-b.x.org"])
        assert a == b

    def test_duplicates_and_case_collapse(self):
        got = desired_records(["GW-A.x.org", "gw-a.x.org", "gw-a.x.org."])
        assert len(got) == 1
        assert got[0].target == "gw-a.x.org"

    def test_it_is_capped(self):
        """A joining node should not fan out across the whole network on every
        refresh."""
        got = desired_records(["gw-%d.x.org" % i for i in range(20)])
        assert len(got) == DEFAULTS["srv_maximum"]

    def test_blank_names_are_dropped(self):
        assert desired_records(["", "   ", None, "gw-a.x.org"]) == [
            Desired("gw-a.x.org", 10, 10, 443)]

    def test_equal_weight_so_resolvers_spread_the_load(self):
        """A joining node should not always ask the same gateway first."""
        got = desired_records(["gw-a.x.org", "gw-b.x.org"])
        assert len({item.weight for item in got}) == 1
        assert len({item.priority for item in got}) == 1


class TestPlan:
    def test_new_gateways_are_created(self):
        steps = plan(existing("gw-a.x.org"), desired_records(["gw-a.x.org", "gw-b.x.org"]))
        assert [c.target for c in steps["create"]] == ["gw-b.x.org"]
        assert steps["remove"] == []

    def test_departed_gateways_are_removed(self):
        steps = plan(existing("gw-a.x.org", "gw-b.x.org"), desired_records(["gw-a.x.org"]))
        assert [target_of(r["answer"]) for r in steps["remove"]] == ["gw-b.x.org"]

    def test_an_unchanged_set_is_a_no_op(self):
        steps = plan(existing("gw-a.x.org"), desired_records(["gw-a.x.org"]))
        assert steps["create"] == [] and steps["remove"] == []

    def test_the_packed_answer_is_parsed_not_compared_whole(self):
        """Name.com packs an SRV as "{weight} {port} {target}" in one string.
        Comparing that against a bare hostname never matches, so every
        reconcile would delete each record and recreate it — churning the zone
        and leaving a window on each pass where a joining node finds fewer
        sources than exist."""
        steps = plan(existing("gw-a.x.org"), desired_records(["gw-a.x.org"]))
        assert steps["create"] == [] and steps["remove"] == []

    def test_target_of_handles_the_real_shapes(self):
        assert target_of("10 443 gw-a.x.org") == "gw-a.x.org"
        assert target_of("10 443 gw-a.x.org.") == "gw-a.x.org"
        assert target_of("1 5061 sip.example.com") == "sip.example.com"
        assert target_of("") == ""
        assert target_of(None) == ""

    def test_it_refuses_to_empty_the_record_set(self):
        """A name that answers with nothing is worse for a joining node than a
        stale target it can skip — it has nowhere to fail over TO."""
        steps = plan(existing("gw-a.x.org", "gw-b.x.org"), [])
        assert steps["remove"] == []
        assert any("Refusing to empty" in w for w in steps["warnings"])


class FakeNameCom:
    def __init__(self, records=None, fail_list=False):
        self.records = list(records or [])
        self.created = []
        self.deleted = []
        self.fail_list = fail_list

    async def list_srv_records(self, host):
        if self.fail_list:
            raise RuntimeError("name.com is unhappy")
        return self.records

    async def create_srv_record(self, host, target, ttl, priority=10, weight=10, port=443):
        self.created.append(target)
        return {"id": 999, "answer": target}

    async def delete_record(self, record_id):
        self.deleted.append(record_id)


class TestReconcile:
    def test_dry_run_changes_nothing(self):
        """The default. This writes to a live zone, and the first run should be
        read rather than trusted."""
        client = FakeNameCom(existing("gw-a.x.org"))
        steps = asyncio.run(reconcile(client, ["gw-a.x.org", "gw-b.x.org"]))
        assert steps["applied"] is False
        assert client.created == [] and client.deleted == []
        assert [c.target for c in steps["create"]] == ["gw-b.x.org"]

    def test_apply_creates_before_removing(self):
        """The other order leaves a window where the set is short or empty, and
        a node bootstrapping in it sees fewer sources than exist."""
        order = []
        client = FakeNameCom(existing("gw-old.x.org"))

        async def create(host, target, ttl, **kw):
            order.append("create")
            return {}

        async def delete(record_id):
            order.append("delete")

        client.create_srv_record = create
        client.delete_record = delete
        asyncio.run(reconcile(client, ["gw-new.x.org"], apply=True))
        assert order == ["create", "delete"]

    def test_a_failed_listing_changes_nothing(self):
        """Without knowing what exists there is no plan, and guessing would
        delete records that are fine."""
        client = FakeNameCom(fail_list=True)
        steps = asyncio.run(reconcile(client, ["gw-a.x.org"], apply=True))
        assert steps["applied"] is False
        assert client.created == [] and client.deleted == []

    def test_no_healthy_gateways_removes_nothing_even_when_applying(self):
        client = FakeNameCom(existing("gw-a.x.org"))
        steps = asyncio.run(reconcile(client, [], apply=True))
        assert client.deleted == []
        assert any("Refusing to empty" in w for w in steps["warnings"])

    def test_one_failed_write_does_not_abort_the_rest(self):
        """A transient API error on one record should not leave the others
        unpublished — the next reconcile would just repeat the whole thing."""
        client = FakeNameCom([])
        calls = []

        async def create(host, target, ttl, **kw):
            calls.append(target)
            if target == "gw-a.x.org":
                raise RuntimeError("nope")
            return {}

        client.create_srv_record = create
        asyncio.run(reconcile(client, ["gw-a.x.org", "gw-b.x.org"], apply=True))
        assert calls == ["gw-a.x.org", "gw-b.x.org"]
