"""Moderation-filtered content similarity over Phase 2 embeddings."""

from model.Analytics import ContentFeature
from services.analytics.features import cosine_similarity
from shared import db


def similar_feature_rows(content_type, content_id, limit=12, candidate_limit=500):
    source = db.session.query(ContentFeature).filter_by(
        content_type=content_type, content_id=str(content_id)
    ).one_or_none()
    if source is None or not source.moderation_eligible:
        return []
    candidates = (
        db.session.query(ContentFeature)
        .filter(
            ContentFeature.content_type == content_type,
            ContentFeature.content_id != str(content_id),
            ContentFeature.moderation_eligible.is_(True),
        )
        .order_by(ContentFeature.updated_at.desc())
        .limit(candidate_limit)
        .all()
    )
    scored = [(cosine_similarity(source.embedding, row.embedding), row.quality_score or 0.0, row) for row in candidates]
    scored.sort(key=lambda item: (item[0], item[1], item[2].content_id), reverse=True)
    return [row for _similarity, _quality, row in scored[:limit]]


def related_threads(thread, limit=12):
    from model.Thread import Thread

    rows = similar_feature_rows("thread", thread.id, limit=limit)
    ids = [int(row.content_id) for row in rows if row.content_id.isdigit()]
    by_id = {row.id: row for row in db.session.query(Thread).filter(Thread.id.in_(ids)).all()} if ids else {}
    return [by_id[item] for item in ids if item in by_id]
