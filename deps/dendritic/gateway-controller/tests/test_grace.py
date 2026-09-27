"""Letting a reliable gateway drop out briefly without losing its name.

The cost of grace is real and easy to miss: a graced record points DNS at a
machine that is not answering. One of those among nine healthy ones costs a few
readers a retry. Nine among one is a site that looks broken to almost everybody.
So these tests are mostly about the bounds, not the benefit.
"""

from __future__ import annotations

import pytest

from backend.grace import (
    DEFAULTS,
    Candidate,
    _share_allowance,
    certificate_note,
    decide,
    standing,
)

HOUR = 3600
DAY = 86400


def gw(name, healthy=True, standing_value=1.0, down=0.0, age=30 * DAY):
    return Candidate(hostname=name, healthy=healthy, standing=standing_value,
                     unhealthy_seconds=down, age_seconds=age)


class TestStanding:
    def test_a_spotless_gateway_scores_top(self):
        assert standing(0, 30 * DAY, DAY) == 1.0

    def test_failures_dominate(self):
        assert standing(1, 30 * DAY, DAY) == pytest.approx(0.5)
        assert standing(3, 30 * DAY, DAY) == pytest.approx(0.25)

    def test_age_is_a_gate_not_credit(self):
        """A gateway up for a year that fails constantly has not earned
        anything, and treating longevity as credit would say otherwise."""
        assert standing(0, HOUR, DAY) == 0.0
        assert standing(99, 365 * DAY, DAY) < 0.05

    def test_junk_does_not_crash_it(self):
        assert standing(None, 30 * DAY, DAY) == 1.0
        assert standing(-5, 30 * DAY, DAY) == 1.0


class TestBounds:
    def test_a_brief_blip_keeps_the_record(self):
        result = decide([gw("gw1"), gw("gw2"), gw("gw3"),
                         gw("gw4", healthy=False, down=60)])
        assert result["keep"] == ["gw4"]

    def test_a_long_outage_loses_it(self):
        """The bound that stops a graced record becoming a permanent one
        pointing at a machine that is never coming back."""
        result = decide([gw("gw1"), gw("gw2"), gw("gw3"),
                         gw("gw4", healthy=False, down=10 * HOUR)])
        assert result["keep"] == []
        assert "grace lasts" in result["drop"][0]["why"]

    def test_low_standing_gets_no_grace(self):
        result = decide([gw("gw1"), gw("gw2"), gw("gw3"),
                         gw("flaky", healthy=False, standing_value=0.2, down=60)])
        assert result["keep"] == []
        assert "standing" in result["drop"][0]["why"]

    def test_a_new_gateway_gets_no_grace(self):
        """One registered five minutes ago and immediately unhealthy would
        otherwise qualify on a spotless failure count."""
        result = decide([gw("gw1"), gw("gw2"), gw("gw3"),
                         gw("new", healthy=False, down=60, age=600)])
        assert result["keep"] == []
        assert "grace needs" in result["drop"][0]["why"]


class TestShareCap:
    def test_a_correlated_outage_does_not_publish_mostly_dead_addresses(self):
        """A time bound alone is not enough: one datacentre going down takes
        many gateways out at the same moment, which is exactly when the time
        bound is least protective."""
        candidates = [gw("up1")] + [
            gw("down%d" % i, healthy=False, down=60) for i in range(9)
        ]
        result = decide(candidates)
        # 1 healthy, 34% cap -> at most 0 graced (0.34/0.66 * 1 = 0.5 -> 0)
        assert result["graced"] == 0
        assert result["would_publish"] == 1

    def test_grace_scales_with_the_healthy_pool(self):
        candidates = [gw("up%d" % i) for i in range(10)] + [
            gw("down%d" % i, healthy=False, down=60) for i in range(9)
        ]
        result = decide(candidates)
        assert result["graced"] > 0
        share = result["graced"] / result["would_publish"]
        assert share <= DEFAULTS["grace_max_share"] + 1e-9

    def test_the_cap_is_measured_against_the_final_published_set(self):
        """Each graced record enlarges the total it is measured against.
        Computing it against the healthy set alone lets the real share drift
        above the cap exactly when there are fewest healthy gateways."""
        # 2 healthy, cap 0.5 -> keep 2 (2/4 = 0.5), not 1.
        assert _share_allowance(2, 5, 0.5) == 2
        assert _share_allowance(10, 99, 0.34) == 5

    def test_degenerate_caps(self):
        assert _share_allowance(5, 3, 0) == 0
        assert _share_allowance(5, 3, 1) == 3
        assert _share_allowance(0, 3, 0.5) == 0

    def test_the_share_cap_is_explained_not_silent(self):
        candidates = [gw("up1")] + [
            gw("down%d" % i, healthy=False, down=60) for i in range(5)
        ]
        result = decide(candidates)
        assert any("share cap" in entry["why"] for entry in result["drop"])


class TestNothingHealthy:
    def test_grace_is_withdrawn_when_no_gateway_is_up(self):
        """Keeping records then publishes only unreachable addresses, and there
        is no healthy gateway to fail over to. Nothing is gained and readers
        wait through every timeout."""
        result = decide([gw("d1", healthy=False, down=60),
                         gw("d2", healthy=False, down=60)])
        assert result["keep"] == []
        assert result["would_publish"] == 0
        assert any("unreachable" in w for w in result["warnings"])


class TestStability:
    def test_the_same_input_gives_the_same_answer(self):
        candidates = [gw("up%d" % i) for i in range(6)] + [
            gw("down%d" % i, healthy=False, down=60, standing_value=1.0)
            for i in range(4)
        ]
        first = decide(candidates)["keep"]
        second = decide(list(reversed(candidates)))["keep"]
        assert first == second

    def test_it_never_raises(self):
        """This runs inside the DNS reconcile. An exception here stops records
        being maintained for everyone."""
        for candidates in ([], [gw("only", healthy=False, down=0)]):
            decide(candidates)


class TestCertificateNote:
    def test_it_corrects_the_obvious_wrong_assumption(self):
        """Keeping the DNS record does not renew anything — a gateway that is
        down cannot complete an HTTP-01 challenge whatever DNS says."""
        note = certificate_note(["gw1"])
        assert "does not renew" in note
        assert "HTTP-01" in note

    def test_nothing_to_say_when_nothing_is_graced(self):
        assert certificate_note([]) is None
