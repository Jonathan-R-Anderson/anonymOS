"""Moderation-filtered Phase 2 embedding retrieval for related videos."""

from services.text_cluster import distinctive_tokens
from shared import db


# Bound the candidate pool so a watch page never triggers an unbounded full-table
# scan. Newest-first; generous for v1 data volumes.
_CANDIDATE_LIMIT = 500


def _video_document(video):
    """Adapt a Video into the dict shape the cluster token helpers expect.

    ``distinctive_tokens`` reads title/description/content/keyword; tags are
    folded into ``content`` and any cached keywords into ``keyword``.
    """
    return {
        "title": getattr(video, "title", "") or "",
        "description": getattr(video, "description", "") or "",
        "content": getattr(video, "tags", "") or "",
        "keyword": getattr(video, "keywords", "") or "",
    }


def video_tokens(video):
    return distinctive_tokens(_video_document(video))


def compute_keywords(title=None, description=None, tags=None):
    """Space-joined distinctive tokens cached on Video.keywords at upload time."""
    document = {
        "title": title or "",
        "description": description or "",
        "content": tags or "",
        "keyword": "",
    }
    return " ".join(sorted(distinctive_tokens(document)))


def related_videos(video, limit=12, surface="video_related", return_result=False):
    """Return up to ``limit`` related Video rows, most-similar first.

    Phase 2 embeddings are the primary score and quality/views break ties. New
    items without a feature row use the bounded Jaccard fallback until the next
    nightly refresh. Ineligible feature rows never enter the result set.
    """
    from model.Video import Video

    candidates = (
        db.session.query(Video)
        .filter(Video.id != video.id)
        .order_by(Video.created_at.desc())
        .limit(_CANDIDATE_LIMIT)
        .all()
    )
    from services.recommendations.engine import recommend_ids
    result = recommend_ids(
        "video", [candidate.id for candidate in candidates], surface,
        limit=limit, anchor_id=video.id, board_scoped=True,
    )
    by_id = {str(candidate.id): candidate for candidate in candidates}
    ranked = [by_id[content_id] for content_id in result.ids if content_id in by_id]
    return (ranked, result) if return_result else ranked
