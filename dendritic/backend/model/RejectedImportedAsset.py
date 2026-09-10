import datetime as _datetime

from shared import db


class RejectedImportedAsset(db.Model):
    """Source-scoped AI refusal; deliberately not a media hash ban."""

    id = db.Column(db.Integer, primary_key=True)
    source_type = db.Column(db.String(128), nullable=False)
    locator = db.Column(db.String(2048), nullable=False)
    reason = db.Column(db.String(255), nullable=True)
    created_at = db.Column(
        db.DateTime, nullable=False, default=_datetime.datetime.utcnow
    )

    __table_args__ = (
        db.UniqueConstraint(
            "source_type", "locator", name="uq_rejected_imported_asset_source"
        ),
    )


def reject_imported_asset(source_type, *locators, reason=None):
    changed = False
    normalized_source = str(source_type)[:128]
    for raw in locators:
        locator = str(raw or "").strip()[:2048]
        if not locator:
            continue
        existing = (
            db.session.query(RejectedImportedAsset)
            .filter_by(source_type=normalized_source, locator=locator)
            .one_or_none()
        )
        if existing is None:
            db.session.add(RejectedImportedAsset(
                source_type=normalized_source,
                locator=locator,
                reason=(reason or "")[:255] or None,
            ))
            changed = True
    return changed


def imported_asset_is_rejected(source_type, *locators):
    values = [str(value).strip()[:2048] for value in locators if str(value or "").strip()]
    if not values:
        return False
    return (
        db.session.query(RejectedImportedAsset.id)
        .filter(
            RejectedImportedAsset.source_type == str(source_type)[:128],
            RejectedImportedAsset.locator.in_(values),
        )
        .first()
        is not None
    )
