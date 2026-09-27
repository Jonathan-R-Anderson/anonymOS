from markdown.inlinepatterns import InlineProcessor
from xml.etree import ElementTree as etree
from sqlalchemy.orm.exc import NoResultFound

from flask import url_for

import cache
from model.Reply import REPLY_REGEXP


def post_url_cache_key(post_id):
    return "post-url-%d" % post_id


def _synthetic_imported_post_url(post_id):
    if post_id < 1_000_000:
        return None
    from model.Thread import Thread

    thread_id = int(post_id) // 1_000_000
    if thread_id <= 0:
        return None
    thread = Thread.query.filter(Thread.id == thread_id).one_or_none()
    if thread is None or thread.source_type == "local":
        return None
    return url_for("threads.view", thread_id=thread.id) + "#" + str(post_id)


def url_for_post(post_id):
    cache_key = post_url_cache_key(post_id)
    cache_connection = cache.Cache()
    cached_url = cache_connection.get(cache_key)
    if cached_url:
        return cached_url
    from model.Thread import Thread
    try:
        thread = Thread.query.filter(Thread.posts.any(id=post_id)).one()
        post_url = url_for("threads.view", thread_id=thread.id) + "#" + str(post_id)
    except NoResultFound:
        post_url = _synthetic_imported_post_url(post_id)
        if post_url is None:
            raise
    cache_connection.set(cache_key, post_url)
    return post_url


class PostReplyPattern(InlineProcessor):
    def __init__(self):
        super().__init__(REPLY_REGEXP)

    def handleMatch(self, match, data):
        reply_id = int(match.group(2))
        try:
            link = etree.Element("a")
            link.attrib["href"] = url_for_post(reply_id)
            link.attrib["class"] = "post-reply"
            link.attrib["data-post-id"] = str(reply_id)
            link.attrib["data-toggle"] = "tooltip"
            link.attrib["data-placement"] = "bottom"
            link.attrib["data-html"] = "true"
            link.attrib["title"] = "<i>Loading...</i>"
            link.attrib["data-loaded"] = "false"
            link.text = ">>%s" % reply_id
            return link, match.start(0), match.end(0)
        except NoResultFound:
            dead_reply = etree.Element("span")
            dead_reply.text = ">>%s" % reply_id
            dead_reply.attrib["class"] = "text-danger"
            return dead_reply, match.start(0), match.end(0)
