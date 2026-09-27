"""Bounded, logged Phase 3 candidate generation and ranking."""

import datetime as _datetime
import hashlib
import math
import os
import time
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from flask import has_request_context, request
from sqlalchemy import func

from model.Analytics import AnalyticsAnonProfile, AnalyticsEvent, AnalyticsUserProfile, ContentFeature
from model.Recommendation import CollaborativeSimilarity, RecommendationInteraction, RecommendationLog
from model.Slip import get_slip
from services.analytics.consent import current_consent
from services.analytics.events import emit_server_event
from services.analytics.features import cosine_similarity, text_embedding
from services.analytics.features import _effective_event_weight
from services.experiments import assign_experiments, log_exposures
from services.recommendations.advanced import advanced_viewer_state, contextual_bandit, sequence_affinity
from model.AdvancedRecommendation import CreatorExposureDaily
from shared import app, db


MODEL_ID = "linear_baseline_v1"
LOG_RETENTION = _datetime.timedelta(days=30)
MAX_CANDIDATES = 500
FREQUENCY_CAP_24H = 3

# ── Data-sufficiency gate ─────────────────────────────────────────────────────
# Recommending is a claim: "this is better for you than what is simply newest".
# Making that claim from one scraped OP and no viewer history is worse than not
# making it — it shuffles a board away from recency for no signal, which reads
# as the board being broken.
#
# So an item is only RANKED when we actually know something about it, and
# personalization only engages once the viewer has a history. Anything that
# fails the gate is still shown; it just falls back to last-post recency
# (Candidate.created_at is Thread.last_updated, i.e. the newest post's time).
RECO_MIN_THREAD_POSTS = 4       # a thread needs a conversation, not just an OP
RECO_MIN_VIEWER_EVENTS = 8      # below this a "profile" is noise
RECO_MIN_RANKABLE_FRACTION = 0.5  # if most of the board is unknown, stay chronological


def _thread_post_counts(content_ids):
    """{content_id: post count} for thread candidates — the conversation-depth
    half of the gate. One grouped query, not one per thread."""
    ids = [int(v) for v in content_ids if str(v).isdigit()]
    if not ids:
        return {}
    try:
        from model.Post import Post
        rows = (
            db.session.query(Post.thread, func.count(Post.id))
            .filter(Post.thread.in_(ids))
            .group_by(Post.thread)
            .all()
        )
        return {str(thread_id): int(count) for thread_id, count in rows}
    except Exception:
        db.session.rollback()
        app.logger.exception("recommendations: post-count gate query failed")
        return {}


def _viewer_has_enough_history(subject_id, profile):
    """True when we know enough about this viewer to personalize for them.

    Deliberately strict: a profile row that exists but is empty is not history.
    """
    if subject_id is None or profile is None:
        return False
    for attribute in ("event_count", "interaction_count", "events_observed", "total_events"):
        value = getattr(profile, attribute, None)
        if isinstance(value, int):
            return value >= RECO_MIN_VIEWER_EVENTS
    # No counter on the profile model — fall back to counting real interactions.
    try:
        count = (
            db.session.query(func.count(RecommendationInteraction.id))
            .filter(RecommendationInteraction.subject_id == subject_id)
            .scalar()
        )
        return int(count or 0) >= RECO_MIN_VIEWER_EVENTS
    except Exception:
        db.session.rollback()
        app.logger.exception("recommendations: viewer-history gate query failed")
        return False


def _rankable(candidate, post_counts):
    """Do we know enough about this item to rank it above something newer?"""
    if candidate.feature is None:
        return False          # no extracted features yet
    if candidate.content_type == "thread":
        if post_counts.get(candidate.content_id, 0) < RECO_MIN_THREAD_POSTS:
            return False      # an OP with no conversation
    return True
FEATURE_ORDER = (
    "recency", "popularity", "quality", "velocity", "completion", "topic_affinity",
    "embedding_affinity", "creator_affinity", "community_affinity", "language_match",
    "collaborative", "anchor_similarity", "negative_affinity", "fatigue",
)
LINEAR_WEIGHTS = {
    "recency": 0.25,
    "popularity": 0.12,
    "quality": 0.20,
    "velocity": 0.08,
    "completion": 0.08,
    "topic_affinity": 0.20,
    "embedding_affinity": 0.15,
    "creator_affinity": 0.12,
    "community_affinity": 0.10,
    "language_match": 0.02,
    "collaborative": 0.25,
    "anchor_similarity": 0.22,
    "negative_affinity": -0.50,
    "fatigue": -0.18,
}
SHADOW_WEIGHTS = dict(LINEAR_WEIGHTS, quality=0.28, completion=0.12, popularity=0.06, negative_affinity=-0.65)
_booster = None
_booster_path = None
_booster_mtime = None


@dataclass
class Candidate:
    content_type: str
    content_id: str
    created_at: _datetime.datetime
    views: int = 0
    creator_id: str = None
    community_id: str = None
    feature: ContentFeature = None
    sources: set = field(default_factory=set)
    components: dict = field(default_factory=dict)
    score: float = 0.0
    seen: bool = False
    exploration: float = 0.0
    # False => we don't know enough about this item to rank it; it falls back to
    # last-post recency BELOW everything we do know about. See _rankable().
    rankable: bool = True

    @property
    def item_id(self):
        return "%s:%s" % (self.content_type, self.content_id)

    @property
    def topic(self):
        values = list((self.feature.tags if self.feature else []) or []) + list((self.feature.keywords if self.feature else []) or [])
        return values[0] if values else "untagged:%s" % self.content_id


@dataclass
class RecommendationResult:
    request_id: str
    model_id: str
    personalized: bool
    mode: str
    ids: list
    metadata: dict
    experiments: list = field(default_factory=list)
    satisfaction_prompt: bool = False


def recommendation_enabled():
    if not app.config.get("RECOMMENDER_ENABLED", True):
        return False
    if has_request_context() and (request.args.get("ranking") or "").strip().lower() in ("chronological", "latest", "off"):
        return False
    return True


def _viewer_state():
    consent = current_consent() if has_request_context() else None
    slip = get_slip() if has_request_context() else None
    subject_id = consent.subject_id if consent is not None and consent.analytics else None
    profile = None
    allowed = bool(
        consent is not None and consent.analytics and consent.personalization
        and app.config.get("ANALYTICS_PERSONALIZATION_ENABLED", False)
    )
    if allowed and consent.slip_id is not None:
        profile = db.session.get(AnalyticsUserProfile, consent.slip_id)
    if allowed and profile is None and subject_id:
        profile = db.session.get(AnalyticsAnonProfile, subject_id)
    return consent, slip, subject_id, profile, allowed


def _content_candidates(content_type, candidate_ids):
    ids = [str(value) for value in candidate_ids][:MAX_CANDIDATES]
    features = {
        row.content_id: row
        for row in db.session.query(ContentFeature).filter(
            ContentFeature.content_type == content_type,
            ContentFeature.content_id.in_(ids),
        ).all()
    }
    candidates = []
    if content_type == "thread":
        from model.Thread import Thread
        rows = db.session.query(Thread).filter(Thread.id.in_([int(value) for value in ids if value.isdigit()])).all()
        by_id = {str(row.id): row for row in rows}
        for content_id in ids:
            row = by_id.get(content_id)
            if row is None:
                continue
            creator_id = None
            if row.posts:
                creator_id = _thread_creator(row)
            candidates.append(Candidate(
                content_type="thread", content_id=content_id,
                created_at=row.last_updated or _datetime.datetime.min,
                views=row.views or 0, creator_id=creator_id,
                community_id=str(row.board), feature=features.get(content_id),
            ))
    elif content_type == "video":
        from model.Video import Video
        rows = db.session.query(Video).filter(Video.id.in_([int(value) for value in ids if value.isdigit()])).all()
        by_id = {str(row.id): row for row in rows}
        for content_id in ids:
            row = by_id.get(content_id)
            if row is None:
                continue
            candidates.append(Candidate(
                content_type="video", content_id=content_id,
                created_at=row.created_at or _datetime.datetime.min,
                views=row.views or 0, creator_id=str(row.slip_id),
                community_id="videos", feature=features.get(content_id),
            ))
    return candidates


def _thread_creator(thread):
    if not thread.posts or thread.posts[0].poster is None:
        return None
    from model.Poster import Poster
    poster = db.session.get(Poster, thread.posts[0].poster)
    if poster is not None and poster.slip is not None:
        return "slip:%s" % poster.slip
    return "poster:%s" % thread.posts[0].poster


def _profile_components(profile, candidate):
    if profile is None or candidate.feature is None:
        return 0.0, 0.0, 0.0
    topics = set((candidate.feature.keywords or [])[:20] + (candidate.feature.tags or [])[:10])
    positive = profile.positive_topics or {}
    negative = profile.negative_topics or {}
    positive_total = max(1.0, max([float(value) for value in positive.values()] or [1.0]))
    negative_total = max(1.0, max([float(value) for value in negative.values()] or [1.0]))
    topic_affinity = min(1.0, sum(float(positive.get(topic, 0.0)) for topic in topics) / positive_total)
    negative_affinity = min(1.0, sum(float(negative.get(topic, 0.0)) for topic in topics) / negative_total)
    profile_embedding = text_embedding(list(positive)[:100])
    embedding_affinity = max(0.0, cosine_similarity(profile_embedding, candidate.feature.embedding or []))
    return topic_affinity, embedding_affinity, negative_affinity


def _collaborative_scores(subject_id, content_type, candidate_ids):
    if not subject_id:
        return {}
    interactions = (
        db.session.query(RecommendationInteraction)
        .filter(RecommendationInteraction.subject_id == subject_id, RecommendationInteraction.net_weight > 0)
        .order_by(RecommendationInteraction.net_weight.desc())
        .limit(20)
        .all()
    )
    scores = defaultdict(float)
    candidate_set = set(candidate_ids)
    for interaction in interactions:
        rows = db.session.query(CollaborativeSimilarity).filter(
            CollaborativeSimilarity.source_type == interaction.content_type,
            CollaborativeSimilarity.source_id == interaction.content_id,
            CollaborativeSimilarity.target_type == content_type,
            CollaborativeSimilarity.target_id.in_(candidate_set),
        ).limit(100).all()
        for row in rows:
            scores[row.target_id] = max(scores[row.target_id], row.score)
    return scores


def _viewer_affinities(subject_id, content_type):
    creators = defaultdict(float)
    communities = defaultdict(float)
    if not subject_id:
        return creators, communities
    events = db.session.query(AnalyticsEvent).filter(
        AnalyticsEvent.anonymous_id == subject_id,
        AnalyticsEvent.content_type == content_type,
        AnalyticsEvent.content_id.isnot(None),
    ).order_by(AnalyticsEvent.event_time.desc()).limit(1000).all()
    item_weights = defaultdict(float)
    for event in events:
        direction, weight = _effective_event_weight(event)
        if direction == "positive" and str(event.content_id).isdigit():
            item_weights[str(event.content_id)] += weight
    if not item_weights:
        return creators, communities
    if content_type == "thread":
        from model.Thread import Thread
        rows = db.session.query(Thread).filter(Thread.id.in_([int(value) for value in item_weights])).all()
        for row in rows:
            weight = item_weights[str(row.id)]
            creator = _thread_creator(row)
            if creator:
                creators[creator] += weight
            communities[str(row.board)] += weight
    elif content_type == "video":
        from model.Video import Video
        rows = db.session.query(Video).filter(Video.id.in_([int(value) for value in item_weights])).all()
        for row in rows:
            creators[str(row.slip_id)] += item_weights[str(row.id)]
            communities["videos"] += item_weights[str(row.id)]
    return creators, communities


def _fatigue(subject_id, content_type):
    served = Counter()
    seen = set()
    if not subject_id:
        return served, seen
    since = _datetime.datetime.utcnow() - _datetime.timedelta(hours=24)
    for log in db.session.query(RecommendationLog).filter(
        RecommendationLog.subject_id == subject_id,
        RecommendationLog.created_at >= since,
        RecommendationLog.content_type == content_type,
    ).all():
        served.update(log.ranked_item_ids or [])
    impression_name = "%s_impression" % content_type
    for (content_id,) in db.session.query(AnalyticsEvent.content_id).filter(
        AnalyticsEvent.anonymous_id == subject_id,
        AnalyticsEvent.event_time >= since,
        AnalyticsEvent.event_name == impression_name,
    ).all():
        if content_id:
            seen.add("%s:%s" % (content_type, content_id))
    return served, seen


def _explicit_negative_items(subject_id, content_type):
    if not subject_id:
        return set()
    rows = db.session.query(AnalyticsEvent.content_id).filter(
        AnalyticsEvent.anonymous_id == subject_id,
        AnalyticsEvent.content_type == content_type,
        AnalyticsEvent.event_name.in_(("hide_selected", "not_interested_selected", "report_submitted")),
        AnalyticsEvent.content_id.isnot(None),
    ).all()
    return {str(content_id) for (content_id,) in rows}


def _load_booster():
    global _booster, _booster_path, _booster_mtime
    path = app.config.get("RECOMMENDER_LIGHTGBM_MODEL_PATH")
    if not path or not os.path.isfile(path):
        return None
    mtime = os.path.getmtime(path)
    if _booster is not None and _booster_path == path and _booster_mtime == mtime:
        return _booster
    try:
        import lightgbm
        _booster = lightgbm.Booster(model_file=path)
        if _booster.num_feature() != len(FEATURE_ORDER):
            raise ValueError("LightGBM artifact expects %s features; Phase 3 supplies %s" % (
                _booster.num_feature(), len(FEATURE_ORDER),
            ))
        _booster_path = path
        _booster_mtime = mtime
        return _booster
    except Exception:
        app.logger.exception("recommendations: failed to load LightGBM artifact %s", path)
        return None


def _score_candidates(candidates, profile, collaborative, anchor_feature, creator_affinity, community_affinity, viewer_language, now, exploration_variant=False, sequence=None, prediction=None, preference=None, bandit=None, conversation_items=None, underexposed_creators=None):
    booster = _load_booster()
    max_views = max([math.log1p(item.views) for item in candidates] or [1.0]) or 1.0
    max_creator_affinity = max([float(value) for value in creator_affinity.values()] or [1.0]) or 1.0
    max_community_affinity = max([float(value) for value in community_affinity.values()] or [1.0]) or 1.0
    for candidate in candidates:
        feature = candidate.feature
        age_hours = max(0.0, (now - candidate.created_at).total_seconds() / 3600.0)
        completion = ((feature.completion_distribution or {}).get("completion_rate", 0.0) if feature else 0.0)
        topic, embedding, negative = _profile_components(profile, candidate)
        components = {
            "recency": math.exp(-age_hours / (24.0 * 14.0)),
            "popularity": math.log1p(candidate.views) / max_views,
            "quality": feature.quality_score if feature else 0.15,
            "velocity": min(1.0, (feature.engagement_velocity if feature else 0.0) / 20.0),
            "completion": float(completion or 0.0),
            "topic_affinity": topic,
            "embedding_affinity": embedding,
            "creator_affinity": float(creator_affinity.get(candidate.creator_id, 0.0)) / max_creator_affinity,
            "community_affinity": float(community_affinity.get(candidate.community_id, 0.0)) / max_community_affinity,
            "language_match": 1.0 if not feature or feature.language in ("und", viewer_language) else 0.0,
            "collaborative": float(collaborative.get(candidate.content_id, 0.0)),
            "anchor_similarity": max(0.0, cosine_similarity(
                anchor_feature.multimodal_embedding or anchor_feature.embedding,
                feature.multimodal_embedding or feature.embedding,
            )) if anchor_feature and feature else 0.0,
            "negative_affinity": negative,
            "fatigue": candidate.components.get("fatigue", 0.0),
        }
        candidate.components = components
        components["sequence_affinity"] = sequence_affinity(sequence, feature)
        components["conversation_continuation"] = 1.0 if candidate.item_id in (conversation_items or set()) else 0.0
        components["creator_discovery"] = 1.0 if candidate.creator_id in (underexposed_creators or set()) else 0.0
        candidate.sources.update(("recent", "popular" if candidate.views else "fresh"))
        if topic or embedding:
            candidate.sources.add("content_profile")
        if components["creator_affinity"]:
            candidate.sources.add("creator_affinity")
        if components["community_affinity"]:
            candidate.sources.add("community_affinity")
        if components["collaborative"]:
            candidate.sources.add("collaborative_item_item")
        if components["anchor_similarity"]:
            candidate.sources.add("content_similarity")
        if components["sequence_affinity"]:
            candidate.sources.add("sequence_intent")
        if components["conversation_continuation"]:
            candidate.sources.add("ongoing_conversation")
        if components["creator_discovery"]:
            candidate.sources.add("underexposed_creator")
        if age_hours <= 48 and candidate.views < 10:
            candidate.sources.add("fresh_exploration")
            candidate.exploration = 0.25 if exploration_variant else 0.10
        if booster is not None:
            candidate.score = float(booster.predict([[components[name] for name in FEATURE_ORDER]])[0])
        else:
            candidate.score = sum(LINEAR_WEIGHTS[name] * components[name] for name in FEATURE_ORDER)
            candidate.score += (0.15 if exploration_variant else 0.03) if candidate.exploration else 0.0
        if sequence is not None:
            engagement = max(0.0, candidate.score)
            satisfaction = max(0.0, components["quality"] - 2.0 * (feature.report_rate if feature else 0.0))
            long_term = 0.45 * components["sequence_affinity"] + 0.25 * components["conversation_continuation"] + 0.30 * components["creator_discovery"]
            safety = max(0.0, 1.0 - (feature.report_rate if feature else 0.0))
            value_weight = prediction.long_term_value if prediction is not None else 0.5
            strength = preference.personalization_strength if preference is not None else 1.0
            candidate.components["objective_engagement"] = engagement
            candidate.components["objective_satisfaction"] = satisfaction
            candidate.components["objective_long_term"] = long_term
            candidate.components["objective_safety"] = safety
            candidate.score = (0.40 * engagement + 0.25 * satisfaction + (0.15 + 0.10 * value_weight) * long_term + 0.20 * safety) * strength
        if bandit is not None:
            bandit_signal = {
                "familiar": components["sequence_affinity"],
                "fresh_creator": components["creator_discovery"],
                "new_topic": max(0.0, 1.0 - max(components["topic_affinity"], components["sequence_affinity"])),
                "cross_format": 1.0 if components["community_affinity"] < 0.1 else 0.0,
            }.get(bandit.arm, 0.0)
            components["bandit_signal"] = bandit_signal
            candidate.score += 0.12 * bandit_signal
            if bandit_signal:
                candidate.sources.add("bandit_%s" % bandit.arm)
                candidate.exploration = max(candidate.exploration, bandit.propensity)


def _explanation(candidate, personalized):
    """Return a bounded explanation without exposing inferred sensitive attributes."""
    components = candidate.components or {}
    if components.get("conversation_continuation"):
        return "Continues a conversation you joined"
    if components.get("creator_discovery"):
        return "From a newer or underexposed creator"
    if components.get("sequence_affinity", 0) > 0.25:
        return "Matches what you are exploring now"
    if "fresh_exploration" in candidate.sources:
        return "New or underexposed content"
    if personalized and components.get("collaborative", 0) > 0.2:
        return "Similar to content you engaged with"
    if personalized and max(components.get("topic_affinity", 0), components.get("embedding_affinity", 0)) > 0.2:
        return "Matches topics you chose to engage with"
    if components.get("anchor_similarity", 0) > 0.2:
        return "Related to what you are viewing"
    if components.get("quality", 0) >= 0.6:
        return "Strong community quality signals"
    if components.get("popularity", 0) >= 0.5:
        return "Popular in this community"
    return "Recent content from this community"


def _diversity_rerank(candidates, limit, board_scoped=False):
    selected = []
    creator_counts = Counter()
    community_counts = Counter()
    seen_count = 0
    remaining = list(candidates)
    community_cap = limit if board_scoped else max(1, int(math.ceil(limit * 0.40)))
    while remaining and len(selected) < limit:
        chosen_index = None
        for index, candidate in enumerate(remaining):
            creator_key = candidate.creator_id or "anonymous:%s" % candidate.content_id
            if creator_counts[creator_key] >= 2:
                continue
            if community_counts[candidate.community_id] >= community_cap:
                continue
            if candidate.seen and seen_count >= 3:
                continue
            if len(selected) >= 2 and selected[-1].topic == selected[-2].topic == candidate.topic:
                continue
            chosen_index = index
            break
        if chosen_index is None:
            break
        candidate = remaining.pop(chosen_index)
        selected.append(candidate)
        creator_counts[candidate.creator_id or "anonymous:%s" % candidate.content_id] += 1
        community_counts[candidate.community_id] += 1
        seen_count += int(candidate.seen)
    return selected


def _creator_discovery_rerank(selected, ordered, limit, board_scoped=False):
    if len(selected) < 2 or any(item.components.get("creator_discovery") for item in selected):
        return selected
    base = selected[:-1]
    creators = Counter(item.creator_id for item in base)
    communities = Counter(item.community_id for item in base)
    community_cap = limit if board_scoped else max(1, int(math.ceil(limit * 0.40)))
    seen_count = sum(int(item.seen) for item in base)
    for candidate in ordered:
        if candidate in selected or not candidate.components.get("creator_discovery"):
            continue
        if creators[candidate.creator_id] >= 2:
            continue
        if communities[candidate.community_id] >= community_cap or (candidate.seen and seen_count >= 3):
            continue
        if len(base) >= 2 and base[-1].topic == base[-2].topic == candidate.topic:
            continue
        selected[-1] = candidate
        break
    return selected[:limit]


def _conversation_items(subject_id, content_type):
    if not subject_id:
        return set()
    rows = db.session.query(AnalyticsEvent.content_id).filter(
        AnalyticsEvent.anonymous_id == subject_id,
        AnalyticsEvent.content_type == content_type,
        AnalyticsEvent.event_name.in_(("comment_submitted", "reply_submitted")),
        AnalyticsEvent.content_id.isnot(None),
    ).all()
    return {"%s:%s" % (content_type, content_id) for (content_id,) in rows}


def _underexposed_creators(content_type, candidates, now):
    since = (now - _datetime.timedelta(days=30)).date()
    counts = dict(db.session.query(CreatorExposureDaily.creator_id, func.sum(CreatorExposureDaily.impressions)).filter(
        CreatorExposureDaily.content_type == content_type,
        CreatorExposureDaily.day >= since,
    ).group_by(CreatorExposureDaily.creator_id).all())
    threshold = sorted(counts.values())[len(counts) // 2] if counts else 10
    return {item.creator_id for item in candidates if item.creator_id is not None and counts.get(item.creator_id, 0) <= threshold}


def recommend_ids(content_type, candidate_ids, surface, limit=None, anchor_id=None, board_scoped=False, chronological=None):
    started = time.perf_counter()
    now = _datetime.datetime.utcnow()
    candidate_ids = list(dict.fromkeys(str(value) for value in candidate_ids))[:MAX_CANDIDATES]
    limit = min(MAX_CANDIDATES, max(1, int(limit or len(candidate_ids) or 1)))
    board_scoped = bool(board_scoped or content_type == "video")
    consent, slip, subject_id, profile, personalization_allowed = _viewer_state()
    assignments = assign_experiments(subject_id, now) if consent is not None and consent.analytics else []
    experiment_ids = [assignment.exposure_id for assignment in assignments]
    experiment_variant = next((assignment.variant for assignment in assignments if assignment.experiment_id == "phase4_recommender_v1"), None)
    if chronological is None:
        chronological = not recommendation_enabled()
    candidates = _content_candidates(content_type, candidate_ids)

    # ── Data-sufficiency gate ────────────────────────────────────────────────
    # Decide what we actually know before deciding how to order anything.
    post_counts = _thread_post_counts([c.content_id for c in candidates]) if content_type == "thread" else {}
    for candidate in candidates:
        candidate.rankable = _rankable(candidate, post_counts)
    rankable_count = sum(1 for c in candidates if c.rankable)
    viewer_ready = _viewer_has_enough_history(subject_id, profile)
    if candidates and not chronological:
        # If most of what we'd be ordering is unknown to us, ranking the handful
        # we do know just scrambles the board for no benefit. Stay chronological.
        if rankable_count / float(len(candidates)) < RECO_MIN_RANKABLE_FRACTION:
            chronological = True
            gate_reason = "insufficient_item_data"
        elif not viewer_ready:
            # We know the items but not the viewer: still rank (popularity,
            # recency, quality signals) — just don't pretend it's personalized.
            gate_reason = "insufficient_viewer_data"
        else:
            gate_reason = None
    else:
        gate_reason = None

    exclusion_reasons = defaultdict(list)
    eligible = []
    for candidate in candidates:
        if candidate.feature is not None and not candidate.feature.moderation_eligible:
            exclusion_reasons["moderation_ineligible"].append(candidate.item_id)
            continue
        eligible.append(candidate)
    candidates = eligible
    negative_items = _explicit_negative_items(subject_id, content_type) if personalization_allowed and not chronological else set()
    if negative_items:
        kept = []
        for candidate in candidates:
            if candidate.content_id in negative_items:
                exclusion_reasons["explicit_negative"].append(candidate.item_id)
            else:
                kept.append(candidate)
        candidates = kept
    served, seen = _fatigue(subject_id if personalization_allowed and not chronological else None, content_type)
    frequency_eligible = []
    for candidate in candidates:
        count = served[candidate.item_id]
        if count >= FREQUENCY_CAP_24H:
            exclusion_reasons["frequency_cap"].append(candidate.item_id)
            continue
        candidate.components["fatigue"] = min(1.0, count / float(FREQUENCY_CAP_24H))
        candidate.seen = candidate.item_id in seen
        frequency_eligible.append(candidate)
    candidates = frequency_eligible
    personalized = personalization_allowed and not chronological and viewer_ready
    sequence = prediction = preference = None
    bandit = None
    conversation_items = set()
    underexposed_creators = set()
    advanced_enabled = personalized and app.config.get("PHASE5_ADVANCED_ENABLED", True)
    if advanced_enabled:
        sequence, prediction, preference = advanced_viewer_state(subject_id)
        muted_topics = set((preference.muted_topics if preference else []) or [])
        excluded_creators = set((preference.excluded_creators if preference else []) or [])
        if muted_topics or excluded_creators:
            kept = []
            for candidate in candidates:
                topics = set((candidate.feature.tags or []) + (candidate.feature.keywords or [])) if candidate.feature else set()
                if topics & muted_topics:
                    exclusion_reasons["muted_topic"].append(candidate.item_id)
                elif candidate.creator_id in excluded_creators:
                    exclusion_reasons["excluded_creator"].append(candidate.item_id)
                else:
                    kept.append(candidate)
            candidates = kept
        conversation_items = _conversation_items(subject_id, content_type)
        underexposed_creators = _underexposed_creators(content_type, candidates, now)
        session_depth = request.args.get("session_depth", 0) if has_request_context() else 0
        try:
            session_depth = int(session_depth)
        except (TypeError, ValueError):
            session_depth = 0
        bandit = contextual_bandit(
            subject_id, surface, content_type, session_depth,
            enabled=preference.exploration_enabled if preference is not None else True,
        )
    anchor_feature = None
    if anchor_id is not None:
        anchor_feature = db.session.query(ContentFeature).filter_by(content_type=content_type, content_id=str(anchor_id)).one_or_none()
    collaborative = _collaborative_scores(subject_id, content_type, [item.content_id for item in candidates]) if personalized else {}
    creator_affinity, community_affinity = _viewer_affinities(subject_id, content_type) if personalized else ({}, {})
    viewer_language = "en"
    if has_request_context():
        viewer_language = (request.accept_languages.best_match(["en"]) or "und").split("-", 1)[0]
    model_id = "chronological_v1"
    mode = "chronological"
    if chronological:
        for candidate in candidates:
            candidate.score = candidate.created_at.timestamp() if candidate.created_at != _datetime.datetime.min else 0.0
            candidate.sources.add("chronological")
        ranked = sorted(candidates, key=lambda item: (item.created_at, item.content_id), reverse=True)[:limit]
        ranked_ids = {item.item_id for item in ranked}
        omitted = [item.item_id for item in candidates if item.item_id not in ranked_ids]
        if omitted:
            exclusion_reasons["rank_cutoff"].extend(omitted)
    else:
        _score_candidates(
            candidates, profile if personalized else None, collaborative, anchor_feature,
            creator_affinity, community_affinity, viewer_language, now,
            exploration_variant=experiment_variant == "exploration",
            sequence=sequence, prediction=prediction, preference=preference, bandit=bandit,
            conversation_items=conversation_items, underexposed_creators=underexposed_creators,
        )
        model_id = "lightgbm:%s" % os.path.basename(_booster_path) if _load_booster() is not None else MODEL_ID
        if advanced_enabled:
            model_id = "advanced_multiobjective_v1"
        mode = "personalized" if personalized else "baseline"
        # Sort key leads with `rankable` so an item we know nothing about can
        # never outrank one we do — even when the scorer returns a negative
        # score. Within the unrankable tail the remaining key is created_at,
        # i.e. Thread.last_updated, i.e. the newest post: recency fallback.
        ordered = sorted(
            candidates,
            key=lambda item: (item.rankable, item.score, item.created_at, item.content_id),
            reverse=True,
        )
        ranked = _diversity_rerank(ordered, limit, board_scoped=board_scoped)
        if advanced_enabled and (preference is None or preference.exploration_enabled):
            ranked = _creator_discovery_rerank(ranked, ordered, limit, board_scoped=board_scoped)
        ranked_ids = {item.item_id for item in ranked}
        reason = "rank_cutoff" if len(ranked) >= limit else "diversity_cap"
        omitted = [item.item_id for item in candidates if item.item_id not in ranked_ids]
        if omitted:
            exclusion_reasons[reason].extend(omitted)
    request_id = str(uuid.uuid4())
    latency_ms = round((time.perf_counter() - started) * 1000.0, 3)
    candidate_item_ids = [item.item_id for item in candidates]
    ranked_item_ids = [item.item_id for item in ranked]
    candidate_sources = [".".join(sorted(item.sources)) for item in candidates]
    sources = [".".join(sorted(item.sources)) for item in ranked]
    scores = [round(float(item.score), 8) for item in ranked]
    score_components = [{key: round(float(value), 8) for key, value in item.components.items()} for item in ranked]
    explanations = [_explanation(item, personalized) for item in ranked]
    shadow_scores = [
        round(sum(SHADOW_WEIGHTS[name] * item.components.get(name, 0.0) for name in FEATURE_ORDER), 8)
        for item in ranked
    ] if not chronological else []
    objective_scores = {}
    for name in ("objective_engagement", "objective_satisfaction", "objective_long_term", "objective_safety"):
        values = [item.components.get(name) for item in ranked if name in item.components]
        if values:
            objective_scores[name] = round(sum(values) / len(values), 8)
    satisfaction_prompt = bool(
        subject_id and ranked and app.config.get("RECOMMENDER_SATISFACTION_PROMPTS_ENABLED", True)
        and int(hashlib.sha256((request_id + subject_id).encode("utf-8")).hexdigest()[:8], 16) % 100
        < int(app.config.get("RECOMMENDER_SATISFACTION_PROMPT_PERCENT", 5))
    )
    log = RecommendationLog(
        request_id=request_id, subject_id=subject_id,
        slip_id=slip.id if slip is not None and subject_id is not None else None,
        surface=surface, content_type=content_type, mode=mode, model_id=model_id,
        personalized=personalized, candidate_item_ids=candidate_item_ids, ranked_item_ids=ranked_item_ids,
        positions=list(range(len(ranked))), scores=scores, candidate_sources=candidate_sources,
        ranked_sources=sources,
        score_components=score_components, exclusion_reasons=dict(exclusion_reasons), experiment_ids=experiment_ids,
        exploration_propensities=[item.exploration for item in ranked], latency_ms=latency_ms,
        explanations=explanations, shadow_model_id=None if chronological else "multi_objective_shadow_v1",
        shadow_scores=shadow_scores,
        objective_scores=objective_scores,
        policy_context=bandit.context_key if bandit else None,
        bandit_arm=bandit.arm if bandit else None,
        bandit_propensity=bandit.propensity if bandit else None,
        created_at=now, expires_at=now + LOG_RETENTION,
    )
    db.session.add(log)
    log_exposures(assignments, subject_id, slip.id if slip is not None else None, request_id, surface, now)
    db.session.commit()
    emit_server_event(
        "recommendation_served", surface=surface, content_type="recommendation",
        content_id="%s:feed" % content_type, request_id=request_id, model_id=model_id,
        properties={
            "candidate_item_ids": candidate_item_ids,
            "ranked_item_ids": ranked_item_ids,
            "positions": list(range(len(ranked))),
            "candidate_sources": candidate_sources,
            "feature_version": "content-v2",
            "eligibility_filters": ["visible", "moderation", "frequency_cap"],
            "exclusion_reasons": sorted(exclusion_reasons),
            # Why ordering fell back, if it did — otherwise "this board ignored the
            # recommender" is undebuggable from the outside.
            "gate_reason": gate_reason,
            "rankable_count": rankable_count,
            "viewer_ready": viewer_ready,
            "score_components": {key: value for key, value in LINEAR_WEIGHTS.items()},
            "recommendation_surface": surface,
            "exploration_propensity": max([item.exploration for item in ranked] or [0.0]),
        },
        experiment_ids=experiment_ids,
    )
    metadata = {
        item.content_id: {
            "request_id": request_id, "model_id": model_id, "position": index,
            "score": scores[index], "source": sources[index], "personalized": personalized,
            "explanation": explanations[index], "experiment_ids": experiment_ids,
            "satisfaction_prompt": satisfaction_prompt and index == 0,
            "bandit_arm": bandit.arm if bandit else None,
            "bandit_propensity": bandit.propensity if bandit else None,
        }
        for index, item in enumerate(ranked)
    }
    return RecommendationResult(
        request_id=request_id, model_id=model_id, personalized=personalized, mode=mode,
        ids=[item.content_id for item in ranked], metadata=metadata,
        experiments=experiment_ids, satisfaction_prompt=satisfaction_prompt,
    )


def rank_payloads(payloads, content_type, surface, limit=None, anchor_id=None, board_scoped=False, chronological=None):
    by_id = {str(item["id"]): item for item in payloads}
    result = recommend_ids(
        content_type, list(by_id), surface, limit=limit or len(by_id), anchor_id=anchor_id,
        board_scoped=board_scoped, chronological=chronological,
    )
    ranked = []
    for content_id in result.ids:
        item = by_id.get(content_id)
        if item is None:
            continue
        item["_recommendation"] = result.metadata[content_id]
        ranked.append(item)
    return ranked, result


def recommendation_quality_summary(hours=24):
    since = _datetime.datetime.utcnow() - _datetime.timedelta(hours=hours)
    logs = db.session.query(RecommendationLog).filter(RecommendationLog.created_at >= since).all()
    ranked = sum(len(row.ranked_item_ids or []) for row in logs)
    sourced = sum(sum(1 for source in (row.ranked_sources or []) if source) for row in logs)
    personalized = sum(1 for row in logs if row.personalized)
    latency = db.session.query(func.avg(RecommendationLog.latency_ms)).filter(
        RecommendationLog.created_at >= since
    ).scalar()
    source_counts = Counter()
    for row in logs:
        for source_group in row.ranked_sources or []:
            source_counts.update(str(source_group).split("."))
    return {
        "requests": len(logs),
        "ranked_items": ranked,
        "source_coverage_percent": round(100.0 * sourced / ranked, 2) if ranked else 100.0,
        "personalized_requests": personalized,
        "average_latency_ms": round(float(latency), 3) if latency is not None else None,
        "candidate_sources": dict(source_counts),
    }
