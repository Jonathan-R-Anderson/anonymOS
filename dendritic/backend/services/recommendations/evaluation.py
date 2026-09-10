"""Offline and shadow evaluation for recommendation logs."""

import datetime as _datetime
import math
from collections import Counter, defaultdict

from model.Analytics import AnalyticsEvent
from model.Recommendation import RecommendationLog
from shared import db


POSITIVE_EVENTS = frozenset((
    "recommendation_clicked", "bookmark_added", "video_completed", "deep_read_reached",
    "comment_submitted", "share_clicked",
))
NEGATIVE_EVENTS = frozenset(("hide_selected", "not_interested_selected", "report_submitted"))


def _safe_rate(numerator, denominator):
    return round(float(numerator) / denominator, 6) if denominator else 0.0


def _dcg(relevances):
    return sum(float(value) / math.log(index + 2, 2) for index, value in enumerate(relevances))


def offline_evaluation(hours=24 * 7, now=None):
    """Evaluate served rankings only; never treats unexposed candidates as negatives."""
    now = now or _datetime.datetime.utcnow()
    since = now - _datetime.timedelta(hours=hours)
    logs = db.session.query(RecommendationLog).filter(RecommendationLog.created_at >= since).all()
    request_ids = [row.request_id for row in logs]
    events = db.session.query(AnalyticsEvent).filter(
        AnalyticsEvent.request_id.in_(request_ids)
    ).all() if request_ids else []
    by_request = defaultdict(list)
    for event in events:
        by_request[event.request_id].append(event)
    position_impressions = Counter()
    position_clicks = Counter()
    ndcgs = []
    ips_rewards = []
    shadow_pairs = 0
    shadow_top1_agreement = 0
    for log in logs:
        rewards = defaultdict(float)
        for event in by_request.get(log.request_id, []):
            if event.position is not None and event.event_name in ("recommendation_impression", "recommendation_viewed"):
                position_impressions[int(event.position)] += 1
            if event.position is not None and event.event_name == "recommendation_clicked":
                position_clicks[int(event.position)] += 1
            item_id = "%s:%s" % (log.content_type, event.content_id) if event.content_id else None
            if item_id and event.event_name in POSITIVE_EVENTS:
                rewards[item_id] += 1.0
            elif item_id and event.event_name in NEGATIVE_EVENTS:
                rewards[item_id] -= 1.0
        relevance = [max(0.0, rewards.get(item_id, 0.0)) for item_id in (log.ranked_item_ids or [])]
        ideal = sorted(relevance, reverse=True)
        ideal_dcg = _dcg(ideal)
        if ideal_dcg:
            ndcgs.append(_dcg(relevance) / ideal_dcg)
        for item_id, propensity in zip(log.ranked_item_ids or [], log.exploration_propensities or []):
            if propensity and rewards.get(item_id, 0.0):
                ips_rewards.append(rewards[item_id] / max(0.01, float(propensity)))
        if log.shadow_scores and log.scores:
            shadow_pairs += 1
            if max(range(len(log.scores)), key=lambda i: log.scores[i]) == max(range(len(log.shadow_scores)), key=lambda i: log.shadow_scores[i]):
                shadow_top1_agreement += 1
    position_bias = []
    for position in sorted(set(position_impressions) | set(position_clicks)):
        impressions = position_impressions[position]
        clicks = position_clicks[position]
        position_bias.append({
            "position": position,
            "impressions": impressions,
            "clicks": clicks,
            "ctr": _safe_rate(clicks, impressions),
        })
    return {
        "window_hours": hours,
        "requests": len(logs),
        "events": len(events),
        "ndcg_at_served": round(sum(ndcgs) / len(ndcgs), 6) if ndcgs else None,
        "inverse_propensity_reward": round(sum(ips_rewards) / len(ips_rewards), 6) if ips_rewards else None,
        "position_bias": position_bias,
        "shadow_requests": shadow_pairs,
        "shadow_top1_agreement": _safe_rate(shadow_top1_agreement, shadow_pairs) if shadow_pairs else None,
        "limitations": "Only viewport-exposed items are labeled; propensity correction applies to randomized traffic.",
    }


if __name__ == "__main__":
    from shared import app
    with app.app_context():
        print(offline_evaluation())
