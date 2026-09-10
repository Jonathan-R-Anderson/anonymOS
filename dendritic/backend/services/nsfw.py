"""NSFW image classification client (Yahoo open_nsfw via the nsfw-classifier sidecar).

Design, and why it is split this way:

The classifier runs out-of-process (see nsfw-classifier/). Inference is CPU-bound
and the backend runs uWSGI+gevent, where CPU-bound work blocks the whole worker's
event loop rather than just the uploading request. Same shape as the ClamAV
sidecar in services/upload_security.py.

SCORE ONCE, ENFORCE PER BOARD. Every attachment is scored inside
Media.save_attachment and the result is stored on Media.nsfw_score. Enforcement
happens separately, wherever a board is known. That split exists because of a
real bypass: the browser uploads via POST /upload/media BEFORE the post is
submitted, so at storage time there is no board and therefore no per-board policy
to apply. Gating only the direct-upload path in post.get_media_id would be
skipped by every normal browser post. Because the score lives on the row, the
deferred check covers the pre-upload path too.

Policy:
  * A board with nsfw_filter set rejects any image scoring >= the threshold.
  * User-created boards always have it set and cannot turn it off
    (model/Board.py + blueprints/boards.py). Admin-created boards may turn it off.
  * Uploads with no board (avatars, banners, watermarks) are checked against the
    same global threshold, since "all submitted images" should pass the filter and
    there is no board to opt out.
  * VIDEO is scanned too, by extracting one frame (see VIDEO_PREFIX). Toggleable
    via the nsfw_scan_video setting, default ON. A video whose frame cannot be
    decoded is allowed through with a warning rather than blocked, so a codec
    quirk or a missing ffmpeg cannot take all video down.
  * If the classifier is unreachable the upload is ALLOWED unless
    nsfw_fail_closed is on, mirroring the CLAMAV_FAIL_CLOSED precedent. An
    unreachable sidecar must not silently stop the site accepting images.
"""
import os

import requests

from model.SiteSetting import get_setting, set_setting
from shared import app

# SiteSetting keys.
ENABLED_SETTING = "nsfw_filter_enabled"
THRESHOLD_SETTING = "nsfw_threshold"
FAIL_CLOSED_SETTING = "nsfw_fail_closed"
TIMEOUT_SETTING = "nsfw_timeout_seconds"

DEFAULT_THRESHOLD = 0.8
DEFAULT_TIMEOUT_SECONDS = 6.0

# open_nsfw scores a single still frame, so images go straight in.
CLASSIFIABLE_PREFIX = "image/"

# VIDEO IS ALSO SCANNED, by extracting one frame first.
#
# This used to be skipped outright, on the reasoning that "decoding video would put
# ffmpeg work in the request path, and video uploads are already login-gated".
# That reasoning does not cover SCRAPED video: it is imported automatically from
# third-party chans with no login anywhere in the loop, and the import already runs
# ffmpeg on every video to build a thumbnail. The result was a real hole — in
# production 459 imported videos (396 mp4 + 63 webm) had NEVER been scored, while
# images were scored normally, so NSFW video passed straight through.
VIDEO_PREFIX = "video/"
VIDEO_SCAN_SETTING = "nsfw_scan_video"
# One frame, downscaled, straight from stdin to stdout — the same shape as
# Media._FFMPEG_FLAGS, which is known to work on this deployment's static build.
_VIDEO_FRAME_FLAGS = (
    "-i pipe:0 -f mjpeg -frames:v 1 "
    "-vf scale=w=500:h=500:force_original_aspect_ratio=decrease pipe:1"
)
_VIDEO_FRAME_TIMEOUT_SECONDS = float(os.getenv("NSFW_VIDEO_FRAME_TIMEOUT", "20") or 20)


def _truthy(value, default=False):
    raw = (value or "").strip().lower()
    if not raw:
        return default
    return raw in ("1", "true", "on", "yes")


def classifier_url():
    configured = (os.getenv("NSFW_CLASSIFIER_URL") or "").strip().rstrip("/")
    return configured or None


def is_enabled():
    """Global master switch. On by default: the point of the feature is that
    boards are filtered unless an admin opts a board out."""
    return _truthy(get_setting(ENABLED_SETTING, ""), default=True)


def set_enabled(enabled):
    set_setting(ENABLED_SETTING, "1" if enabled else "0")


def threshold():
    """NSFW probability at or above which an image is rejected."""
    try:
        value = float((get_setting(THRESHOLD_SETTING, "") or "").strip() or DEFAULT_THRESHOLD)
    except ValueError:
        return DEFAULT_THRESHOLD
    return min(max(value, 0.0), 1.0)


def set_threshold(value):
    value = min(max(float(value), 0.0), 1.0)
    set_setting(THRESHOLD_SETTING, "%.4f" % value)
    return value


def fail_closed():
    """When on, an unreachable/failing classifier rejects the upload."""
    return _truthy(get_setting(FAIL_CLOSED_SETTING, ""), default=False)


def set_fail_closed(enabled):
    set_setting(FAIL_CLOSED_SETTING, "1" if enabled else "0")


def set_scan_video(enabled):
    set_setting(VIDEO_SCAN_SETTING, "1" if enabled else "0")


def timeout_seconds():
    try:
        value = float((get_setting(TIMEOUT_SETTING, "") or "").strip() or DEFAULT_TIMEOUT_SECONDS)
    except ValueError:
        return DEFAULT_TIMEOUT_SECONDS
    return min(max(value, 0.5), 60.0)


def set_timeout_seconds(value):
    value = min(max(float(value), 0.5), 60.0)
    set_setting(TIMEOUT_SETTING, "%.2f" % value)
    return value


class NsfwUnavailable(Exception):
    """The classifier could not produce a score (down, timed out, errored)."""


def scan_video_enabled():
    """Whether video is scanned by extracting a frame. Default ON."""
    return _truthy(get_setting(VIDEO_SCAN_SETTING, ""), default=True)


def extract_video_frame(data):
    """One JPEG frame from video bytes, or None if it cannot be extracted.

    Returns None rather than raising NsfwUnavailable on failure, and that
    distinction is deliberate: NsfwUnavailable trips `fail_closed`, which would
    reject EVERY video site-wide the moment ffmpeg is missing or a codec is
    unsupported. A frame we cannot decode is "unscannable", not "the classifier is
    down" — so it is allowed through with a warning, matching how
    Media._make_thumbnail already tolerates any ffmpeg problem by falling back to a
    placeholder. ~13% of this deployment's imported mp4s already fail extraction
    (is_animated is False for them), so this path is well travelled.
    """
    if not data:
        return None
    import subprocess

    try:
        # Resolved through Media.storage so there is ONE definition of where the
        # ffmpeg binary lives (a static build at ./ffmpeg/ffmpeg here). Imported
        # lazily: model.Media imports this module, so a top-level import would be
        # circular.
        from model.Media import storage

        ffmpeg_path = storage._get_ffmpeg_path()
    except Exception as exc:
        app.logger.warning("nsfw: cannot locate ffmpeg to scan video (%s)", exc)
        return None

    try:
        result = subprocess.run(
            ("%s %s" % (ffmpeg_path, _VIDEO_FRAME_FLAGS)).split(),
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=_VIDEO_FRAME_TIMEOUT_SECONDS,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        app.logger.warning("nsfw: video frame extraction failed (%s)", exc)
        return None
    if result.returncode != 0 or not result.stdout:
        app.logger.warning(
            "nsfw: ffmpeg produced no frame to scan (rc=%s)", result.returncode
        )
        return None
    return result.stdout


def classify_bytes(data, mimetype):
    """NSFW probability for image OR video bytes, or None when not applicable.

    Video is handled by extracting a single frame and scoring that; see
    VIDEO_PREFIX above for why that is not optional. Returns None (without
    contacting the sidecar) when the filter is off, the type is neither image nor
    scannable video, or no classifier is configured. Raises NsfwUnavailable when a
    classification was expected but could not be obtained, so the caller can apply
    the fail-open/fail-closed policy.
    """
    if not is_enabled():
        return None
    if not mimetype:
        return None
    if not mimetype.startswith(CLASSIFIABLE_PREFIX):
        if mimetype.startswith(VIDEO_PREFIX) and scan_video_enabled():
            frame = extract_video_frame(data)
            if not frame:
                return None
            # Recurse as an image: one code path for the HTTP call, the 400
            # handling and the fail-closed policy.
            return classify_bytes(frame, "image/jpeg")
        return None
    base = classifier_url()
    if not base:
        # Not configured at all: treat as "feature not deployed" rather than a
        # failure, so a site without the sidecar keeps working.
        return None
    if not data:
        return None
    try:
        response = requests.post(
            "%s/classify" % base,
            data=data,
            headers={"Content-Type": mimetype},
            timeout=timeout_seconds(),
        )
    except Exception as exc:
        raise NsfwUnavailable("classifier unreachable: %s" % exc)

    if response.status_code == 400:
        # The sidecar could not decode it as an image. Not a classifier failure,
        # and not evidence of NSFW content, so leave it unscored.
        app.logger.info("nsfw: classifier could not decode upload (%s)", mimetype)
        return None
    if not response.ok:
        raise NsfwUnavailable("classifier returned HTTP %s" % response.status_code)
    try:
        payload = response.json() or {}
        score = float(payload["nsfw_score"])
    except Exception as exc:
        raise NsfwUnavailable("malformed classifier response: %s" % exc)
    return min(max(score, 0.0), 1.0)


def board_filters_nsfw(board):
    """Whether this board rejects NSFW images."""
    if board is None:
        return True  # no board context -> the global policy applies
    return bool(getattr(board, "nsfw_filter", True))


def score_blocks(score, board=None):
    """True when a stored score should be refused for this board."""
    if score is None:
        return False
    if not is_enabled():
        return False
    if not board_filters_nsfw(board):
        return False
    return float(score) >= threshold()


def rejection_message(score):
    return (
        "This image was rejected by the NSFW filter (score %.2f, limit %.2f). "
        "If you believe this is a mistake, contact a moderator."
        % (float(score), threshold())
    )


def health():
    """Sidecar status for the admin panel: (ok, detail)."""
    base = classifier_url()
    if not base:
        return False, "NSFW_CLASSIFIER_URL is not set"
    try:
        response = requests.get("%s/health" % base, timeout=timeout_seconds())
    except Exception as exc:
        return False, "unreachable: %s" % exc
    if not response.ok:
        return False, "HTTP %s" % response.status_code
    try:
        return True, (response.json() or {}).get("model") or "ok"
    except Exception:
        return True, "ok"


def selftest():
    """Ask the sidecar to score generated images, for the admin panel."""
    base = classifier_url()
    if not base:
        return None
    try:
        response = requests.get("%s/selftest" % base, timeout=max(timeout_seconds(), 15.0))
        if not response.ok:
            return None
        return (response.json() or {}).get("scores")
    except Exception:
        return None


__all__ = [
    "NsfwUnavailable", "board_filters_nsfw", "classify_bytes", "classifier_url",
    "fail_closed", "health", "is_enabled", "rejection_message", "score_blocks",
    "selftest", "set_enabled", "set_fail_closed", "set_threshold",
    "set_timeout_seconds", "threshold", "timeout_seconds",
]
