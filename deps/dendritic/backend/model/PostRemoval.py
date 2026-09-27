from sqlalchemy import or_

import cache
from model.Media import Media
from model.Post import Post, post_render_cache_key, CONTEXT_THREAD, CONTEXT_CATALOG
from model.PostReplyPattern import post_url_cache_key
from model.Reply import Reply
from model.ThreadPosts import thread_posts_cache_key 
from shared import app, db


class PostRemoval:
    def delete(self, post_id):
        self.delete_impl(post_id)
        db.session.commit()
        try:
            from services.analytics import emit_server_event
            emit_server_event(
                "comment_deleted",
                surface="moderation",
                content_type="post",
                content_id=post_id,
                properties={"reason": "moderation"},
            )
        except Exception:
            app.logger.exception("analytics event failed for deleted post %s", post_id)
    def delete_impl(self, post_id):
        post = db.session.query(Post).filter(Post.id == post_id).one()
        cache_connection = cache.Cache()
        cache_connection.invalidate(post_url_cache_key(post.id))
        for context in (CONTEXT_THREAD, CONTEXT_CATALOG):
            cache_connection.invalidate(post_render_cache_key(context, post.id))
        cache_connection.invalidate(thread_posts_cache_key(post.thread))
        # Remove the reply-graph links that point at or from this post and FLUSH
        # them to the DB before the post itself is deleted. The reply.reply_from /
        # reply_to columns are NO ACTION foreign keys onto post.id, so if the row
        # deletes get reordered after the post delete in a single commit flush
        # (which happens when the post has no other dependents to force an earlier
        # flush) Postgres rejects "DELETE FROM post" with a reply_reply_from_fkey
        # violation. A direct bulk delete emits the SQL immediately, so the links
        # are gone by the time the post is removed.
        db.session.query(Reply).filter(
            or_(Reply.reply_from == post_id, Reply.reply_to == post_id)
        ).delete(synchronize_session=False)
        db.session.flush()
        media = None
        if post.media is not None:
            media = db.session.query(Media).filter(Media.id == post.media).one_or_none()
        if media:
            media.delete_attachment()
            db.session.delete(media)
        db.session.delete(post)
