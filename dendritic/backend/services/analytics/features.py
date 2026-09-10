"""Phase 2 content-feature and consent-scoped interest-profile pipeline."""

import datetime as _datetime
import hashlib
import math
from collections import defaultdict

from model.Analytics import (
    AnalyticsAnonProfile,
    AnalyticsConsent,
    AnalyticsEvent,
    AnalyticsJobState,
    AnalyticsUserProfile,
    ContentFeature,
)
from services.text_cluster import distinctive_tokens
from shared import app, db


FEATURE_VERSION = "content-v2"
EMBEDDING_MODEL = "feature-hash-64-v1"
MULTIMODAL_MODEL = "multimodal-hash-64-v1"
EMBEDDING_DIMENSIONS = 64
PROFILE_JOB = "phase2_feature_profile_refresh"
PROFILE_REFRESH_INTERVAL = _datetime.timedelta(hours=24)
ACCOUNT_RETENTION = _datetime.timedelta(days=180)
ANON_RETENTION = _datetime.timedelta(days=30)

# Explicit negative actions outweigh passive/weak positive behavior.
POSITIVE_EVENT_WEIGHTS = {
    "thread_opened": 1.0,
    "post_expanded": 1.0,
    "recommendation_clicked": 1.0,
    "content_left_viewport": 3.0,
    "reply_submitted": 6.0,
    "share_clicked": 5.0,
    "bookmark_added": 8.0,
    "follow_added": 7.0,
    "video_completed": 4.0,
}
NEGATIVE_EVENT_WEIGHTS = {
    "recommendation_dismissed": 3.0,
    "video_muted": 3.0,
    "hide_selected": 8.0,
    "not_interested_selected": 8.0,
    "report_submitted": 12.0,
}


def _clamp(value, low=0.0, high=1.0):
    return max(low, min(high, float(value)))


def text_embedding(tokens, dimensions=EMBEDDING_DIMENSIONS):
    """Return a deterministic local feature-hashing embedding.

    It is dependency-free and keeps the representation portable. PostgreSQL
    deployments can later copy the fixed-width vector into pgvector without
    rebuilding the source feature rows.
    """
    vector = [0.0] * dimensions
    for token in tokens:
        digest = hashlib.sha256(str(token).encode("utf-8")).digest()
        index = int.from_bytes(digest[:4], "big") % dimensions
        sign = -1.0 if digest[4] & 1 else 1.0
        vector[index] += sign
    magnitude = math.sqrt(sum(value * value for value in vector))
    if magnitude:
        vector = [round(value / magnitude, 8) for value in vector]
    return vector


def cosine_similarity(left, right):
    if not left or not right or len(left) != len(right):
        return 0.0
    left_norm = math.sqrt(sum(float(value) ** 2 for value in left))
    right_norm = math.sqrt(sum(float(value) ** 2 for value in right))
    if not left_norm or not right_norm:
        return 0.0
    return sum(float(a) * float(b) for a, b in zip(left, right)) / (left_norm * right_norm)


def multimodal_embedding(tokens, media, dimensions=EMBEDDING_DIMENSIONS):
    """Fuse text with bounded media metadata or a supplied local visual vector."""
    text_vector = text_embedding(tokens, dimensions)
    visual = (media or {}).get("visual_embedding")
    if not isinstance(visual, list) or len(visual) != dimensions:
        signals = ["media-count:%s" % int((media or {}).get("count", 0))]
        signals.extend("media-type:%s" % value for value in (media or {}).get("types", []))
        visual = text_embedding(signals, dimensions)
    vector = [0.7 * float(left) + 0.3 * float(right) for left, right in zip(text_vector, visual)]
    magnitude = math.sqrt(sum(value * value for value in vector))
    return [round(value / magnitude, 8) for value in vector] if magnitude else vector


def _document_tokens(title, body, tags=None, cached_keywords=None):
    document = {
        "title": title or "",
        "description": body or "",
        "content": " ".join(tags or []),
        "keyword": cached_keywords or "",
    }
    return sorted(distinctive_tokens(document))


def _empty_event_metrics():
    return {
        "impressions": 0, "reports": 0, "engagements": 0,
        "starts": 0, "completions": 0, "playback": [],
        "progress_bins": [0, 0, 0, 0], "recent_engagements": 0,
    }


def _accumulate_event_metrics(metrics, event, now):
    if event.event_name.endswith("_impression") or event.event_name == "recommendation_viewed":
        metrics["impressions"] += 1
    if event.event_name == "report_submitted":
        metrics["reports"] += 1
    if event.event_name in POSITIVE_EVENT_WEIGHTS:
        metrics["engagements"] += 1
        if event.event_time >= now - _datetime.timedelta(hours=24):
            metrics["recent_engagements"] += 1
    if event.event_name == "video_started":
        metrics["starts"] += 1
    if event.event_name == "video_completed":
        metrics["completions"] += 1
    properties = event.properties or {}
    seconds = properties.get("playback_seconds")
    if isinstance(seconds, (int, float)) and seconds > 0 and len(metrics["playback"]) < 10000:
        metrics["playback"].append(float(seconds))
    progress = properties.get("progress_ratio")
    if isinstance(progress, (int, float)):
        metrics["progress_bins"][min(3, max(0, int(float(progress) * 4)))] += 1


def _event_metrics(metrics):
    report_rate = metrics["reports"] / max(1, metrics["impressions"])
    completion_rate = _clamp(metrics["completions"] / max(1, metrics["starts"]))
    playback = metrics["playback"]
    return {
        "impressions": metrics["impressions"],
        "engagements": metrics["engagements"],
        "report_rate": report_rate,
        "engagement_velocity": float(metrics["recent_engagements"]),
        "completion_distribution": {
            "started": metrics["starts"],
            "completed": metrics["completions"],
            "completion_rate": round(completion_rate, 6),
            "quartiles": metrics["progress_bins"],
        },
        "observed_duration": int(sorted(playback)[len(playback) // 2]) if playback else 0,
    }


def _sentiment(tokens):
    if not tokens:
        return (0.0, 0.0)
    from model.WordSentiment import WordSentiment

    rows = db.session.query(WordSentiment).filter(WordSentiment.word.in_(tokens)).all()
    if not rows:
        return (0.0, 0.0)
    confidence = sum(max(0.0, row.magnitude or 0.0) for row in rows)
    if not confidence:
        return (0.0, 0.0)
    score = sum((row.score or 0.0) * max(0.0, row.magnitude or 0.0) for row in rows) / confidence
    return (round(score, 6), round(min(1.0, confidence / max(1, len(tokens))), 6))


def _upsert_feature(content_type, content_id, title, body, tags, cached_keywords,
                    source_updated_at, media, event_metrics, moderation_reasons):
    tokens = _document_tokens(title, body, tags, cached_keywords)
    metrics = _event_metrics(event_metrics)
    sentiment_score, sentiment_magnitude = _sentiment(tokens)
    word_count = len(("%s %s" % (title or "", body or "")).split())
    estimated = metrics["observed_duration"]
    if not estimated:
        estimated = max(1, int(math.ceil(word_count / 200.0 * 60))) if word_count else 0
    completeness = min(1.0, word_count / 80.0) * 0.25 + min(1.0, len(tags) / 3.0) * 0.10
    engagement = min(1.0, metrics["engagements"] / max(1, metrics["impressions"])) * 0.35
    completion = metrics["completion_distribution"]["completion_rate"] * 0.30
    quality = _clamp(completeness + engagement + completion - min(0.8, metrics["report_rate"] * 2.0))
    row = db.session.query(ContentFeature).filter_by(content_type=content_type, content_id=str(content_id)).one_or_none()
    if row is None:
        row = ContentFeature(content_type=content_type, content_id=str(content_id))
    row.feature_version = FEATURE_VERSION
    row.source_updated_at = source_updated_at
    row.keywords = tokens
    row.tags = sorted(set(tag.lower() for tag in tags if tag))
    row.media = media
    row.embedding = text_embedding(tokens)
    row.embedding_model = EMBEDDING_MODEL
    row.multimodal_embedding = multimodal_embedding(tokens, media)
    row.multimodal_model = MULTIMODAL_MODEL
    row.language = "en" if tokens else "und"
    row.sentiment_score = sentiment_score
    row.sentiment_magnitude = sentiment_magnitude
    row.quality_score = round(quality, 6)
    row.report_rate = round(metrics["report_rate"], 6)
    row.engagement_velocity = round(metrics["engagement_velocity"], 6)
    row.completion_distribution = metrics["completion_distribution"]
    row.estimated_duration_seconds = estimated
    row.moderation_eligible = not moderation_reasons
    row.moderation_reasons = sorted(set(moderation_reasons))
    row.updated_at = _datetime.datetime.utcnow()
    db.session.add(row)
    return row


def refresh_content_features():
    """Refresh all current user-visible content rows, including sparse imports."""
    from model.BlockedMediaHash import BlockedMediaHash
    from model.Media import Media
    from model.Post import Post
    from model.Thread import Thread
    from model.Video import Video

    metrics_by_item = defaultdict(_empty_event_metrics)
    feature_types = ("thread", "post", "comment", "video", "image")
    metric_now = _datetime.datetime.utcnow()
    for event in db.session.query(AnalyticsEvent).filter(AnalyticsEvent.content_type.in_(feature_types)).yield_per(2000):
        if event.content_id:
            _accumulate_event_metrics(metrics_by_item[(event.content_type, event.content_id)], event, metric_now)
    blocked_hashes = {value for (value,) in db.session.query(BlockedMediaHash.sha256).all()}
    media_by_id = {row.id: row for row in db.session.query(Media).all()}
    op_by_thread = {}
    media_ids_by_thread = defaultdict(list)
    posts = db.session.query(Post).order_by(Post.thread.asc(), Post.datetime.asc()).all()
    for post in posts:
        op_by_thread.setdefault(post.thread, post)
        if post.media is not None:
            media_ids_by_thread[post.thread].append(post.media)

    seen = set()
    threads = db.session.query(Thread).all()
    threads_by_id = {thread.id: thread for thread in threads}
    tags_by_thread = {
        thread.id: [tag.name for tag in (thread.tags or []) if getattr(tag, "name", None)]
        for thread in threads
    }
    for thread in threads:
        content_id = str(thread.id)
        seen.add(("thread", content_id))
        op = op_by_thread.get(thread.id)
        tags = tags_by_thread[thread.id]
        media_rows = [media_by_id[item] for item in media_ids_by_thread.get(thread.id, []) if item in media_by_id]
        reasons = []
        if op is None and thread.source_type == "local":
            reasons.append("missing_root_post")
        if any(media.sha256 in blocked_hashes for media in media_rows if media.sha256):
            reasons.append("blocked_media")
        _upsert_feature(
            "thread", content_id, getattr(op, "subject", None), getattr(op, "body", None), tags, None,
            thread.last_updated, {"count": len(media_rows), "types": sorted(set(row.mimetype for row in media_rows))},
            metrics_by_item[("thread", content_id)], reasons,
        )

    for post in posts:
        content_id = str(post.id)
        seen.add(("post", content_id))
        media_row = media_by_id.get(post.media) if post.media is not None else None
        reasons = ["blocked_media"] if media_row is not None and media_row.sha256 in blocked_hashes else []
        thread = threads_by_id.get(post.thread)
        _upsert_feature(
            "post", content_id, post.subject, post.body, tags_by_thread.get(post.thread, []), None,
            post.datetime or getattr(thread, "last_updated", None),
            {"count": int(media_row is not None), "types": [media_row.mimetype] if media_row else []},
            metrics_by_item[("post", content_id)], reasons,
        )

        media_content_type = None
        if media_row is not None and (media_row.mimetype or "").startswith("image/"):
            media_content_type = "image"
        elif media_row is not None and (media_row.mimetype or "").startswith("video/"):
            media_content_type = "video"
        if media_content_type is not None:
            media_content_id = "media:%s" % media_row.id
            seen.add((media_content_type, media_content_id))
            _upsert_feature(
                media_content_type, media_content_id, post.subject, post.body, tags_by_thread.get(post.thread, []), None,
                post.datetime, {"count": 1, "types": [media_row.mimetype]},
                metrics_by_item[(media_content_type, media_content_id)], reasons,
            )

    videos = db.session.query(Video).all()
    for video in videos:
        content_id = str(video.id)
        seen.add(("video", content_id))
        media_row = media_by_id.get(video.media_id)
        reasons = []
        if media_row is None:
            reasons.append("missing_media")
        elif media_row.sha256 and media_row.sha256 in blocked_hashes:
            reasons.append("blocked_media")
        _upsert_feature(
            "video", content_id, video.title, video.description, video.tag_list(), video.keywords,
            video.created_at, {"count": int(media_row is not None), "types": [media_row.mimetype] if media_row else []},
            metrics_by_item[("video", content_id)], reasons,
        )

    from model.Video import VideoComment
    videos_by_id = {video.id: video for video in videos}
    for comment in db.session.query(VideoComment).all():
        content_id = str(comment.id)
        seen.add(("comment", content_id))
        parent_video = videos_by_id.get(comment.video_id)
        _upsert_feature(
            "comment", content_id, None, comment.body,
            parent_video.tag_list() if parent_video is not None else [], None,
            comment.created_at, {"count": 0, "types": []},
            metrics_by_item[("comment", content_id)], [],
        )

    stale = db.session.query(ContentFeature).filter(ContentFeature.content_type.in_(feature_types)).all()
    removed = 0
    for row in stale:
        if (row.content_type, row.content_id) not in seen:
            db.session.delete(row)
            removed += 1
    db.session.commit()
    return {"refreshed": len(seen), "removed": removed}


def _effective_event_weight(event):
    if event.event_name == "content_left_viewport":
        engaged = (event.properties or {}).get("engaged_ms", 0)
        if isinstance(engaged, (int, float)) and engaged < 2000:
            return ("negative", 2.0)  # passive fast-abandon signal
        if not isinstance(engaged, (int, float)) or engaged < 10000:
            return (None, 0.0)
    if event.event_name in NEGATIVE_EVENT_WEIGHTS:
        return ("negative", NEGATIVE_EVENT_WEIGHTS[event.event_name])
    if event.event_name in POSITIVE_EVENT_WEIGHTS:
        return ("positive", POSITIVE_EVENT_WEIGHTS[event.event_name])
    return (None, 0.0)


def build_profile_values(events, features):
    positive = defaultdict(float)
    negative = defaultdict(float)
    content_types = defaultdict(float)
    used = 0
    last_event_at = None
    for event in events:
        direction, weight = _effective_event_weight(event)
        feature = features.get((event.content_type, event.content_id))
        if direction is None or feature is None:
            continue
        target = positive if direction == "positive" else negative
        for topic in list(feature.keywords or [])[:20] + list(feature.tags or [])[:10]:
            target[str(topic)] += weight
        content_types[event.content_type] += weight if direction == "positive" else -weight
        used += 1
        if last_event_at is None or event.event_time > last_event_at:
            last_event_at = event.event_time
    def top(values):
        return {key: round(value, 4) for key, value in sorted(values.items(), key=lambda item: (-item[1], item[0]))[:100]}
    return top(positive), top(negative), top(content_types), used, last_event_at


def refresh_user_profiles(now=None):
    now = now or _datetime.datetime.utcnow()
    if not app.config.get("ANALYTICS_PERSONALIZATION_ENABLED", False):
        accounts = db.session.query(AnalyticsUserProfile).delete(synchronize_session=False)
        anonymous = db.session.query(AnalyticsAnonProfile).delete(synchronize_session=False)
        db.session.commit()
        return {"accounts": 0, "anonymous": 0, "removed_while_gated": accounts + anonymous}
    features = {(row.content_type, row.content_id): row for row in db.session.query(ContentFeature).all()}
    consented = db.session.query(AnalyticsConsent).filter(
        AnalyticsConsent.analytics.is_(True), AnalyticsConsent.personalization.is_(True)
    ).all()
    valid_slips = set()
    valid_subjects = set()
    for consent in consented:
        events = db.session.query(AnalyticsEvent).filter(AnalyticsEvent.anonymous_id == consent.subject_id).all()
        values = build_profile_values(events, features)
        if consent.slip_id is not None:
            account_events = db.session.query(AnalyticsEvent).filter(AnalyticsEvent.slip_id == consent.slip_id).all()
            values = build_profile_values(account_events, features)
            if not values[3]:
                continue
            expiry = values[4] + ACCOUNT_RETENTION
            if expiry <= now:
                continue
            valid_slips.add(consent.slip_id)
            row = db.session.get(AnalyticsUserProfile, consent.slip_id) or AnalyticsUserProfile(slip_id=consent.slip_id)
        else:
            if not values[3]:
                continue
            expiry = values[4] + ANON_RETENTION
            if expiry <= now:
                continue
            valid_subjects.add(consent.subject_id)
            row = db.session.get(AnalyticsAnonProfile, consent.subject_id) or AnalyticsAnonProfile(subject_id=consent.subject_id)
        row.positive_topics, row.negative_topics, row.content_type_weights, row.source_event_count, row.last_event_at = values
        row.updated_at = now
        row.expires_at = expiry
        db.session.add(row)

    # Withdrawal or consent changes remove derived profiles at the next refresh.
    for row in db.session.query(AnalyticsUserProfile).all():
        if row.slip_id not in valid_slips or row.expires_at <= now:
            db.session.delete(row)
    for row in db.session.query(AnalyticsAnonProfile).all():
        if row.subject_id not in valid_subjects or row.expires_at <= now:
            db.session.delete(row)
    db.session.commit()
    return {"accounts": len(valid_slips), "anonymous": len(valid_subjects)}


def refresh_phase2(now=None, force=False):
    now = now or _datetime.datetime.utcnow()
    state = db.session.get(AnalyticsJobState, PROFILE_JOB)
    if not force and state is not None and state.last_completed_at and now - state.last_completed_at < PROFILE_REFRESH_INTERVAL:
        return {"status": "not_due", "last_completed_at": state.last_completed_at}
    if state is None:
        state = AnalyticsJobState(name=PROFILE_JOB)
    state.status = "running"
    state.last_started_at = now
    db.session.add(state)
    db.session.commit()
    try:
        content = refresh_content_features()
        # A second guard protects against an accidentally enabled profile gate:
        # only explicitly personalized consents are ever selected by the job.
        profiles = refresh_user_profiles(now=now)
        state = db.session.get(AnalyticsJobState, PROFILE_JOB)
        state.status = "complete"
        state.last_completed_at = now
        state.detail = {"content": content, "profiles": profiles, "feature_version": FEATURE_VERSION}
        db.session.commit()
        return state.detail
    except Exception as exc:
        db.session.rollback()
        state = db.session.get(AnalyticsJobState, PROFILE_JOB) or AnalyticsJobState(name=PROFILE_JOB)
        state.status = "error"
        state.detail = {"error": str(exc)[:500]}
        db.session.add(state)
        db.session.commit()
        raise


def update_online_profile(events, consent):
    """Best-effort 30-day short-term profile counters in Redis."""
    if consent is None or not consent.personalization or not events or app.config.get("STORE_PROVIDER") != "REDIS":
        return
    try:
        import keystore
        client = keystore.make_redis()
        key = "analytics:profile:%s" % consent.subject_id
        pipeline = client.pipeline()
        for event in events:
            direction, weight = _effective_event_weight(event)
            if direction:
                pipeline.hincrbyfloat(key, "%s:%s:%s" % (direction, event.content_type or "none", event.content_id or "none"), weight)
        pipeline.expire(key, int(ANON_RETENTION.total_seconds()))
        pipeline.execute()
    except Exception:
        app.logger.exception("analytics: short-term profile update failed")


def feature_quality_summary():
    """Operational coverage and refresh state for the admin quality page."""
    from model.Media import Media
    from model.Post import Post
    from model.Thread import Thread
    from model.Video import Video, VideoComment

    expected = (
        db.session.query(Thread).count()
        + db.session.query(Post).count()
        + db.session.query(Video).count()
        + db.session.query(VideoComment).count()
        + db.session.query(Post.media)
        .join(Media, Post.media == Media.id)
        .filter(Post.media.isnot(None), Media.mimetype.like("image/%") | Media.mimetype.like("video/%"))
        .distinct()
        .count()
    )
    actual = db.session.query(ContentFeature).count()
    eligible = db.session.query(ContentFeature).filter(ContentFeature.moderation_eligible.is_(True)).count()
    state = db.session.get(AnalyticsJobState, PROFILE_JOB)
    return {
        "expected_content": expected,
        "feature_rows": actual,
        "coverage_percent": round(actual * 100.0 / expected, 2) if expected else 100.0,
        "eligible_rows": eligible,
        "account_profiles": db.session.query(AnalyticsUserProfile).count(),
        "anonymous_profiles": db.session.query(AnalyticsAnonProfile).count(),
        "job_status": state.status if state is not None else "not_run",
        "last_completed_at": state.last_completed_at if state is not None else None,
    }
