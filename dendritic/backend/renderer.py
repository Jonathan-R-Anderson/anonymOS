import json
import re
from urllib.parse import urljoin

from flask import render_template, request, url_for
import requests

from shared import app


def _thread_opengraph(thread, thread_id, subject, board_name, board_title):
    """Open Graph / Twitter Card metadata so a shared thread link renders as a
    rich embed card on other sites."""
    posts = thread.get("posts") or []
    first = posts[0] if posts else {}
    title = (subject or "").strip() or ("/%s/ — thread" % board_name if board_name else "Thread")
    body_text = re.sub(r"<[^>]+>", " ", first.get("body") or "")
    body_text = re.sub(r"\s+", " ", body_text).strip()
    if len(body_text) > 200:
        body_text = body_text[:197].rstrip() + "…"
    try:
        url = url_for("threads.view", thread_id=thread_id, _external=True)
    except Exception:
        url = None
    image = None
    thumb = first.get("thumb_url")
    if thumb:
        try:
            image = urljoin(request.url_root, thumb)
        except Exception:
            image = None
    return {
        "title": title,
        "description": body_text or (board_title or board_name or "Discussion thread"),
        "url": url,
        "image": image,
        "site_name": app.config.get("INSTANCE_NAME") or "maniwani",
    }


FIREHOSE_TEMPLATE = "react-index.html"
FIREHOSE_RENDER_URL = "/render/firehose"
CATALOG_TEMPLATE = "react-catalog.html"
CATALOG_RENDER_URL = "/render/catalog"
BOARD_INDEX_TEMPLATE = "react-board-index.html"
BOARD_INDEX_RENDER_URL = "/render/board-index"
THREAD_TEMPLATE = "react-thread.html"
THREAD_RENDER_URL = "/render/thread"
NEW_THREAD_TEMPLATE = "react-new-thread.html"
NEW_THREAD_RENDER_URL = "/render/new-thread"
NEW_POST_TEMPLATE = "react-new-post.html"
NEW_POST_RENDER_URL = "/render/new-post"
GALLERY_TEMPLATE = "react-gallery.html"
GALLERY_RENDER_URL = "/render/gallery"
VIDEOS_TEMPLATE = "react-videos.html"
VIDEOS_RENDER_URL = "/render/videos"
VIDEO_WATCH_TEMPLATE = "react-video-watch.html"
VIDEO_WATCH_RENDER_URL = "/render/videowatch"


def render_react_template(template, renderer_path, data):
    renderer_url = app.config["RENDERER_HOST"] + renderer_path
    payload = {"template": template, "data": data}
    response = requests.post(renderer_url, json=payload, timeout=10)
    response.raise_for_status()
    return response.text


def _catalog_store(catalog, captcha=None, media_delivery=None):
    return {
        "posts": [],
        "threads": catalog["threads"],
        "captcha": captcha or {},
        "mediaDelivery": media_delivery or {},
        "catalogInfo": {
            "board": "",
            "styles": catalog["tag_styles"],
        },
    }


def _thread_store(thread, captcha=None, media_delivery=None, remote_reply=None):
    return {
        "posts": thread["posts"],
        "threads": [],
        "captcha": captcha or {},
        "mediaDelivery": media_delivery or {},
        "remoteReply": remote_reply or {},
        "catalogInfo": {
            "board": "",
            "styles": [],
        },
    }


def _react_catalog_shell(
    board_name,
    board_id,
    catalog,
    extra_data=None,
    board_title=None,
    board_metrics_urls=None,
    board_banners=None,
    board_moderation_url=None,
    board_settings_url=None,
    media_delivery_config=None,
    distributed_config=None,
    board_custom_css=None,
    board_custom_js=None,
    board_custom_html=None,
    sidebar=None,
):
    template = render_template(
        CATALOG_TEMPLATE,
        board_name=board_name,
        board_id=board_id,
        board_title=board_title or board_name,
        board_metrics_start_url=(board_metrics_urls or {}).get("start"),
        board_metrics_ping_url=(board_metrics_urls or {}).get("ping"),
        board_banners=board_banners or [],
        board_moderation_url=board_moderation_url,
        board_settings_url=board_settings_url,
        media_delivery_config=media_delivery_config or {},
        distributed_config=distributed_config or {},
        board_custom_css=board_custom_css,
        board_custom_js=board_custom_js,
        board_custom_html=board_custom_html,
        sidebar=sidebar,
    )
    store_data = json.dumps(_catalog_store(
        catalog,
        (extra_data or {}).get("captcha"),
        media_delivery=media_delivery_config,
    ))
    return (
        template
        .replace("STORE_DATA", store_data)
        .replace("BOARD_ID", str(board_id))
        .replace("TEMPLATE_CONTENT", "")
    )


def _react_thread_shell(
    thread,
    thread_id,
    extra_data=None,
    board_metrics_urls=None,
    board_name=None,
    board_title=None,
    board_banners=None,
    board_moderation_url=None,
    media_delivery_config=None,
    distributed_config=None,
    sidebar=None,
):
    subject = ""
    if thread.get("posts"):
        subject = thread["posts"][0].get("subject") or ""
    template = render_template(
        THREAD_TEMPLATE,
        subject=subject,
        thread_id=thread_id,
        board_metrics_start_url=(board_metrics_urls or {}).get("start"),
        board_metrics_ping_url=(board_metrics_urls or {}).get("ping"),
        board_name=board_name,
        board_title=board_title or board_name,
        board_banners=board_banners or [],
        board_moderation_url=board_moderation_url,
        media_delivery_config=media_delivery_config or {},
        distributed_config=distributed_config or {},
        sidebar=sidebar,
    )
    store_data = json.dumps(_thread_store(
        thread,
        (extra_data or {}).get("captcha"),
        media_delivery=media_delivery_config,
        remote_reply=(extra_data or {}).get("remoteReply"),
    ))
    return (
        template
        .replace("STORE_DATA", store_data)
        .replace("THREAD_ID", str(thread_id))
        .replace("TEMPLATE_CONTENT", "")
    )


def render_firehose(firehose, greeting, news_stories=None, extra_data=None, front_page_updates=None, warrant_canary=None):
    # Cache-only, never a live chain read. GET / has taken this site down once
    # already by doing network I/O inside a page render — every other route
    # stayed fine, which made it look like a network fault rather than a render
    # one. If nothing is cached the front page simply omits the figure.
    from services.token_supply import cached_summary

    try:
        supply = cached_summary()
    except Exception:
        supply = None

    base_template = render_template(
        FIREHOSE_TEMPLATE,
        greeting=greeting,
        supply=supply,
        news_stories=news_stories or [],
        front_page_updates=front_page_updates or [],
        warrant_canary=warrant_canary,
    )
    return render_react_template(base_template, FIREHOSE_RENDER_URL, {"firehose": firehose})


def render_catalog(
    catalog,
    board_name,
    board_id,
    extra_data=None,
    board_title=None,
    board_metrics_urls=None,
    board_banners=None,
    prefer_shell=False,
    board_moderation_url=None,
    board_settings_url=None,
    media_delivery_config=None,
    distributed_config=None,
    board_custom_css=None,
    board_custom_js=None,
    board_custom_html=None,
    sidebar=None,
):
    if prefer_shell:
        return _react_catalog_shell(
            board_name,
            board_id,
            catalog,
            extra_data,
            board_title=board_title,
            board_metrics_urls=board_metrics_urls,
            board_banners=board_banners,
            board_moderation_url=board_moderation_url,
            board_settings_url=board_settings_url,
            media_delivery_config=media_delivery_config,
            distributed_config=distributed_config,
            board_custom_css=board_custom_css,
            board_custom_js=board_custom_js,
            board_custom_html=board_custom_html,
            sidebar=sidebar,
        )
    data = {"catalog": catalog, "board_id": board_id, "mediaDelivery": media_delivery_config or {}}
    if extra_data:
        data.update(extra_data)
    base_template = render_template(
        CATALOG_TEMPLATE,
        board_name=board_name,
        board_id=board_id,
        board_title=board_title or board_name,
        board_metrics_start_url=(board_metrics_urls or {}).get("start"),
        board_metrics_ping_url=(board_metrics_urls or {}).get("ping"),
        board_banners=board_banners or [],
        board_moderation_url=board_moderation_url,
        board_settings_url=board_settings_url,
        media_delivery_config=media_delivery_config or {},
        distributed_config=distributed_config or {},
        board_custom_css=board_custom_css,
        board_custom_js=board_custom_js,
        board_custom_html=board_custom_html,
        sidebar=sidebar,
    )
    try:
        return render_react_template(base_template, CATALOG_RENDER_URL, data)
    except Exception:
        app.logger.exception("Catalog renderer failed for board %s; falling back to client-side shell", board_id)
        return _react_catalog_shell(
            board_name,
            board_id,
            catalog,
            extra_data,
            board_title=board_title,
            board_metrics_urls=board_metrics_urls,
            board_banners=board_banners,
            board_moderation_url=board_moderation_url,
            board_settings_url=board_settings_url,
            media_delivery_config=media_delivery_config,
            distributed_config=distributed_config,
            board_custom_css=board_custom_css,
            board_custom_js=board_custom_js,
            board_custom_html=board_custom_html,
            sidebar=sidebar,
        )

def render_board_index(items):
    data = {"items": items}
    base_template = render_template(BOARD_INDEX_TEMPLATE)
    return render_react_template(base_template, BOARD_INDEX_RENDER_URL, data)

def render_thread(
    thread,
    thread_id,
    public_thread_id=None,
    extra_data=None,
    board_metrics_urls=None,
    board_name=None,
    board_title=None,
    board_banners=None,
    board_moderation_url=None,
    media_delivery_config=None,
    distributed_config=None,
    sidebar=None,
):
    data = {
        "thread": thread,
        "thread_id": thread_id,
        "public_thread_id": public_thread_id,
    }
    if extra_data:
        data.update(extra_data)
    subject = ""
    if thread.get("posts"):
        subject = thread["posts"][0].get("subject") or ""
    base_template = render_template(
        THREAD_TEMPLATE,
        subject=subject,
        thread_id=thread_id,
        public_thread_id=public_thread_id,
        opengraph=_thread_opengraph(thread, thread_id, subject, board_name, board_title),
        board_metrics_start_url=(board_metrics_urls or {}).get("start"),
        board_metrics_ping_url=(board_metrics_urls or {}).get("ping"),
        board_name=board_name,
        board_title=board_title or board_name,
        board_banners=board_banners or [],
        board_moderation_url=board_moderation_url,
        media_delivery_config=media_delivery_config or {},
        distributed_config=distributed_config or {},
        sidebar=sidebar,
    )
    try:
        return render_react_template(base_template, THREAD_RENDER_URL, data)
    except Exception:
        app.logger.exception("Thread renderer failed for thread %s; falling back to client-side shell", thread_id)
        return _react_thread_shell(
            thread,
            thread_id,
            extra_data,
            board_metrics_urls=board_metrics_urls,
            board_name=board_name,
            board_title=board_title,
            board_banners=board_banners,
            board_moderation_url=board_moderation_url,
            media_delivery_config=media_delivery_config,
            distributed_config=distributed_config,
            sidebar=sidebar,
        )


def render_new_thread_form(board_id, extra_data=None):
    data = {"board_id": board_id}
    if extra_data:
        data.update(extra_data)
    base_template = render_template(NEW_THREAD_TEMPLATE)
    return render_react_template(base_template, NEW_THREAD_RENDER_URL, data)


def render_new_post_form(
    thread_id,
    extra_data=None,
    reply_to=None,
    body_value=None,
    subject_value=None,
    name_value=None,
    cancel_outbound_id=None,
):
    data = {"thread_id": thread_id}
    if reply_to:
        data["reply_to"] = reply_to
    if extra_data:
        data.update(extra_data)
    if body_value is not None:
        data["body_value"] = body_value
    if subject_value is not None:
        data["subject_value"] = subject_value
    if name_value is not None:
        data["name_value"] = name_value
    if cancel_outbound_id is not None:
        data["cancel_outbound_id"] = cancel_outbound_id
    base_template = render_template(NEW_POST_TEMPLATE, thread_id=thread_id)
    return render_react_template(base_template, NEW_POST_RENDER_URL, data)


def render_thread_gallery(board, thread_id, posts, media_delivery_config=None):
    base_template = render_template(
        GALLERY_TEMPLATE,
        board=board,
        thread_id=thread_id,
        media_delivery_config=media_delivery_config,
        gallery_posts=posts,
    )
    data = {
        "posts": posts,
        "mediaDelivery": media_delivery_config or {},
    }
    return render_react_template(base_template, GALLERY_RENDER_URL, data)


# ---------------------------------------------------------------------------
# /videos — the listing and watch stores ARE the JSON posted to the Node
# renderer, so the SSR path and the client-only shell fallback emit an
# identical window._STORE.
# ---------------------------------------------------------------------------


def _react_videos_shell(store, media_delivery_config=None):
    template = render_template(
        VIDEOS_TEMPLATE,
        media_delivery_config=media_delivery_config or {},
    )
    return (
        template
        .replace("STORE_DATA", json.dumps(store))
        .replace("TEMPLATE_CONTENT", "")
    )


def render_videos(store, query=None, media_delivery_config=None):
    base_template = render_template(
        VIDEOS_TEMPLATE,
        media_delivery_config=media_delivery_config or {},
    )
    try:
        return render_react_template(base_template, VIDEOS_RENDER_URL, store)
    except Exception:
        app.logger.exception("Videos renderer failed; falling back to client-side shell")
        return _react_videos_shell(store, media_delivery_config=media_delivery_config)


def _react_video_watch_shell(store, media_delivery_config=None, video_title=None):
    template = render_template(
        VIDEO_WATCH_TEMPLATE,
        media_delivery_config=media_delivery_config or {},
        video_title=video_title,
    )
    return (
        template
        .replace("STORE_DATA", json.dumps(store))
        .replace("TEMPLATE_CONTENT", "")
    )


def render_video_watch(store, media_delivery_config=None):
    video_title = (store.get("video") or {}).get("title") if isinstance(store, dict) else None
    base_template = render_template(
        VIDEO_WATCH_TEMPLATE,
        media_delivery_config=media_delivery_config or (store or {}).get("mediaDelivery") or {},
        video_title=video_title,
    )
    try:
        return render_react_template(base_template, VIDEO_WATCH_RENDER_URL, store)
    except Exception:
        app.logger.exception("Video watch renderer failed; falling back to client-side shell")
        return _react_video_watch_shell(
            store,
            media_delivery_config=media_delivery_config,
            video_title=video_title,
        )
