import datetime as _datetime
from flask import url_for

from bleach import clean
from markdown import markdown
from werkzeug.utils import escape

import cache
from model.AntiAi import AntiAiExtension
from model.PostReplyExtension import PostReplyExtension
from model.SpacingExtension import SpacingExtension
from model.Spoiler import SpoilerExtension
from model.ThreadRootExtension import ThreadRootExtension
from outputmixin import OutputMixin
from shared import db


# adapted from https://github.com/Wenzil/mdx_bleach
ALLOWED_TAGS = [
    "ul",
    "ol",
    "li",
    "p",
    "pre",
    "code",
    "blockquote",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "hr",
    "br",
    "strong",
    "em",
    "a",
    "img",
    "div",
    "span"
]
# TODO: strip inline images, remove need to not strip div
ALLOWED_ATTRIBUTES = {
    "a": ["href", "title", "class", "data-post-id", "data-toggle", "data-placement", "data-html",
          "data-loaded"],
    "img": ["src", "title", "alt"],
    # `data-note` numbers a footnote so the article template can wrap it in the
    # anchor a footnote link needs. `id` is deliberately NOT allowed on any tag:
    # ids come from the template, never from text an author controls, or an
    # author could collide with the page's own anchors.
    "div": ["class", "data-note"],
    "span": ["class"]
}
CONTEXT_CATALOG, CONTEXT_THREAD = range(2)


def post_render_cache_key(context, post_id):
    return "post-render-%d-%d" % (context, post_id)


def render_markdown(source, extensions):
    return clean(markdown(source, extensions=extensions), ALLOWED_TAGS, ALLOWED_ATTRIBUTES)


def render_post_collection(posts, context, extensions):
    cache_connection = cache.Cache()
    for post in posts:
        cache_key = post_render_cache_key(context, post["id"])
        cached_render = cache_connection.get(cache_key)
        if cached_render:
            post["body"] = cached_render
            continue
        rendered_markdown = render_markdown(post["body"], extensions)
        cache_connection.set(cache_key, rendered_markdown)
        post["body"] = rendered_markdown


def render_for_catalog(posts):
    render_post_collection(posts, CONTEXT_CATALOG, [PostReplyExtension(),
                                                    SpoilerExtension(),
                                                    AntiAiExtension(),
                                                    SpacingExtension()])
  

def render_for_threads(posts):
    render_post_collection(posts, CONTEXT_THREAD, [ThreadRootExtension(), PostReplyExtension(),
                                                   SpoilerExtension(),
                                                   AntiAiExtension(),
                                                   SpacingExtension()])


def render_individual(post):
    cache_key = post_render_cache_key(CONTEXT_THREAD, post["id"])
    cache_connection = cache.Cache()
    cached_render = cache_connection.get(cache_key)
    if cached_render:
        post["body"] = cached_render
        return
    rendered_markdown = render_markdown(post["body"], [ThreadRootExtension(),
                                                       PostReplyExtension(),
                                                       SpoilerExtension(),
                                                       AntiAiExtension(),
                                                       SpacingExtension()])
    cache_connection.set(cache_key, rendered_markdown)
    post["body"] = rendered_markdown


MAX_BODY_LENGTH = 4096


class Post(OutputMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(MAX_BODY_LENGTH), nullable=False)
    subject = db.Column(db.String(64), nullable=True)
    thread = db.Column(db.Integer, db.ForeignKey("thread.id"), nullable=False)
    datetime = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)
    poster = db.Column(db.Integer, db.ForeignKey("poster.id"), nullable=True)
    media = db.Column(db.Integer, db.ForeignKey("media.id", ondelete="CASCADE"), nullable=True)
    spoiler = db.Column(db.Boolean, nullable=True)
    author_name = db.Column(db.String(128), nullable=True)
    tripcode = db.Column(db.String(16), nullable=True)
    source_type = db.Column(db.String(128), nullable=False, default="local")
    source_name = db.Column(db.String(64), nullable=True)
    source_post_id = db.Column(db.String(128), nullable=True)
    source_parent_post_id = db.Column(db.String(128), nullable=True)
    source_url = db.Column(db.String, nullable=True)
    external_media_url = db.Column(db.String, nullable=True)
    # Federated source watermark (e.g. the origin site's favicon URL) + label,
    # carried over NNTP so imported posts stay attributed to their source.
    source_watermark_url = db.Column(db.String, nullable=True)
    source_watermark_label = db.Column(db.String(128), nullable=True)
