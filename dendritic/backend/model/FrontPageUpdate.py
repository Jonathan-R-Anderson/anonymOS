"""Admin-authored front-page updates ("current events" posts). Rendered on the
front page above the auto-synthesized news carousel. Body is admin-authored HTML
(rendered as-is, so images/gifs/embeds work) — same trust model as the editable
front-page greeting; only admins can post these (route is admin-gated)."""
import datetime as _datetime

from shared import db


class FrontPageUpdate(db.Model):
    __tablename__ = "front_page_update"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=True)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow, index=True)
    created_by_slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=True)

    @property
    def created_at_display(self):
        return self.created_at.strftime("%b %d, %Y") if self.created_at else ""


def recent_front_page_updates(limit=6):
    """Newest-first published updates for the front page."""
    try:
        return (
            db.session.query(FrontPageUpdate)
            .order_by(FrontPageUpdate.created_at.desc(), FrontPageUpdate.id.desc())
            .limit(limit)
            .all()
        )
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
        return []


def create_front_page_update(title, body, created_by_slip_id=None):
    title = (title or "").strip()[:200] or None
    body = (body or "").strip()
    if not body:
        return None
    update = FrontPageUpdate(title=title, body=body, created_by_slip_id=created_by_slip_id)
    db.session.add(update)
    return update


def delete_front_page_update(update_id):
    deleted = (
        db.session.query(FrontPageUpdate)
        .filter(FrontPageUpdate.id == update_id)
        .delete(synchronize_session=False)
    )
    return bool(deleted)
