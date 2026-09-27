"""The stand-in image served when real media cannot be delivered.

Shared by /image-proxy (remote fetch failed / blocked) and /upload/thumb (the
stored object is gone), so a missing image looks the same everywhere.

Served from here, never fetched. /image-proxy used to redirect to
https://picsum.photos/300/200 — a third-party RANDOM-image service — which meant
a missing image showed an unrelated stock photo, handed every viewer's IP to a
third party, and rendered as a blank white box whenever that service was
unreachable.

An SVG keeps it dependency-free: no binary asset to ship, scales to any tile
size, and the greys are mid-tone so it sits acceptably on light and dark themes
alike (it cannot see the theme's CSS variables from inside an <img>).
"""
from flask import Response


PLACEHOLDER_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 300 200" '
    'width="300" height="200" role="img" aria-label="Image unavailable">'
    '<rect width="300" height="200" fill="#8b9099"/>'
    '<g fill="none" stroke="#e8eaed" stroke-width="6" stroke-linejoin="round" '
    'stroke-linecap="round" opacity=".85">'
    '<rect x="106" y="72" width="88" height="66" rx="6"/>'
    '<circle cx="130" cy="94" r="8"/>'
    '<path d="M110 130l26-24 20 18 14-12 16 14"/>'
    '</g>'
    '<text x="150" y="164" text-anchor="middle" fill="#e8eaed" opacity=".85" '
    'font-family="-apple-system,Segoe UI,Roboto,sans-serif" font-size="15">'
    'image unavailable</text>'
    '</svg>'
)


def placeholder_response(max_age=300):
    """A local stand-in for an image we could not serve.

    200, not 404: the browser has to actually paint something. A 404 leaves a
    broken-image box — and on a catalog tile, where the text overlay only
    appears on hover, that reads as a blank white tile and makes the whole page
    look broken.

    Short cache by default because the usual causes are transient (a source
    rate-limiting us, a slow fetch), so the real image gets another chance soon.
    """
    response = Response(PLACEHOLDER_SVG, content_type="image/svg+xml")
    response.headers["Cache-Control"] = "public, max-age=%d" % max_age
    return response
