"""Make a cached page safe to serve when nothing behind it works.

A snapshot is served during an outage. Every interactive control on it points at
an origin that is, by definition, not answering — so a page that still LOOKS
interactive is worse than one that plainly is not:

  * a post box that accepts text and loses it is silent data loss, and the
    reader has no way to know their words went nowhere;
  * a login form that appears to work invites someone to type a password into a
    page served by a volunteer's machine;
  * a purchase button that half-submits is the worst outcome available.

So every form is replaced by a visible refusal. Not disabled-but-present:
replaced, because a disabled control that a stylesheet failed to load still
looks clickable, and a missing stylesheet is exactly the kind of thing that
happens in the situation this exists for.

WHY THE STANDARD LIBRARY AND NOT BEAUTIFULSOUP
----------------------------------------------
This ran first on BeautifulSoup, which is not installed in the backend image —
so every page silently failed to rewrite and the whole snapshot was refused.
Adding the dependency was the obvious fix and the wrong one: this code runs to
produce the artifact that is served WHEN THINGS ARE BROKEN, and the fewer things
it needs, the fewer ways it has to be unavailable exactly then.

`html.parser` is in the standard library, is a real parser, and is enough. What
it is emphatically not is a regular expression: rewriting HTML by pattern
matching fails on a `<form>` inside a comment, an attribute containing the word,
or a tag split across lines, and it fails silently.

CSRF TOKENS
-----------
Stripped wherever they appear. They are per-session and already useless by the
time a snapshot is served, but they are also the one part of a rendered page
that belongs to whoever the renderer was — and a snapshot is published to
strangers.
"""

from html import escape
from html.parser import HTMLParser

from services.snapshot_banner import BANNER_HTML, DISABLED_NOTICE

# Field names carrying session-scoped secrets. A snapshot is a public artifact;
# none of these belong in one.
_SENSITIVE_FIELDS = ("csrf", "authenticity_token", "_token", "session", "nonce")

# Elements that never have a closing tag, so the depth tracking below must not
# wait for one.
_VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link",
         "meta", "param", "source", "track", "wbr"}


class _ReadOnlyRewriter(HTMLParser):
    """Emit the document with every interactive control neutralised."""

    def __init__(self, banner):
        # convert_charrefs=False so entities pass through byte-identical rather
        # than being decoded and re-encoded into something subtly different.
        HTMLParser.__init__(self, convert_charrefs=False)
        self.out = []
        self.banner = banner
        self._form_depth = 0
        self._banner_done = False

    # -- helpers ---------------------------------------------------------
    def _emit(self, text):
        # Everything inside a <form> is dropped: the form is replaced whole, so
        # its contents must not leak through as loose markup.
        if self._form_depth == 0:
            self.out.append(text)

    def _attrs(self, attrs, drop=(), add=()):
        parts = []
        for name, value in attrs:
            if name.lower() in drop:
                continue
            if value is None:
                parts.append(" %s" % name)
            else:
                parts.append(' %s="%s"' % (name, escape(value, quote=True)))
        for name, value in add:
            parts.append(' %s="%s"' % (name, escape(value, quote=True)))
        return "".join(parts)

    @staticmethod
    def _is_sensitive(attrs):
        for name, value in attrs:
            if name.lower() in ("name", "id") and value:
                lowered = value.lower()
                if any(marker in lowered for marker in _SENSITIVE_FIELDS):
                    return True
        return False

    # -- parser callbacks ------------------------------------------------
    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag == "form":
            if self._form_depth == 0:
                self.out.append(
                    '<div class="syndichan-emergency-disabled">%s</div>'
                    % escape(DISABLED_NOTICE))
            self._form_depth += 1
            return
        if self._form_depth:
            return
        if tag in ("input", "meta") and self._is_sensitive(attrs):
            return
        if tag == "button":
            self._emit("<button%s>" % self._attrs(
                attrs, drop=("onclick",),
                add=(("disabled", "disabled"), ("title", DISABLED_NOTICE))))
            return
        if tag == "a":
            # Anchors that mutate state through a handler rather than a form.
            self._emit("<a%s>" % self._attrs(attrs, drop=("onclick",)))
            return
        self._emit("<%s%s>" % (tag, self._attrs(attrs, drop=("onclick",))))
        if tag == "body" and not self._banner_done:
            self._banner_done = True
            self.out.append(self.banner)

    def handle_startendtag(self, tag, attrs):
        tag = tag.lower()
        if self._form_depth:
            return
        if tag in ("input", "meta") and self._is_sensitive(attrs):
            return
        self._emit("<%s%s/>" % (tag, self._attrs(attrs, drop=("onclick",))))

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag == "form":
            if self._form_depth:
                self._form_depth -= 1
            return
        if tag in _VOID:
            return
        self._emit("</%s>" % tag)

    def handle_data(self, data):
        self._emit(data)

    def handle_comment(self, data):
        self._emit("<!--%s-->" % data)

    def handle_decl(self, decl):
        self._emit("<!%s>" % decl)

    def handle_entityref(self, name):
        self._emit("&%s;" % name)

    def handle_charref(self, name):
        self._emit("&#%s;" % name)

    def handle_pi(self, data):
        self._emit("<?%s>" % data)


def rewrite_html(html, snapshot_label=""):
    """Return ``(html, took_something_away)``, or ``(None, True)`` to drop it.

    None means the caller must DROP the route rather than publish it. A page
    that cannot be made read-only is not a page worth serving during an outage.

    THE SECOND RETURN VALUE IS WHAT PHASE 6 RESTS ON
    ------------------------------------------------
    Some pages have nothing to take away — a FAQ, an explainer, a formatting
    guide. The rewriter removes no form, no token, no handler, and the result is
    byte-identical to what the origin served.

    Such a page is not an "emergency copy" of anything. It IS the page. So it
    gets no banner and can be served from cache during ORDINARY operation
    without misleading anyone or removing a capability, which is the whole basis
    of origin offloading.

    A page that DID lose something is different in kind: serving it normally
    would silently take away a post box or a login. Those keep the banner and
    are only ever served when the origin cannot answer.
    """
    try:
        # Rewritten once WITHOUT a banner, so the comparison answers "did this
        # page lose anything" rather than "did we add a notice to it".
        bare = _ReadOnlyRewriter("")
        bare.feed(html or "")
        bare.close()
    except Exception:
        return None, True
    stripped = "".join(bare.out)
    if not stripped.strip():
        return None, True

    if stripped == (html or ""):
        # Nothing was removed. This is the origin's own bytes.
        return stripped, False

    try:
        rewriter = _ReadOnlyRewriter(BANNER_HTML % escape(snapshot_label or "unknown"))
        rewriter.feed(html or "")
        rewriter.close()
    except Exception:
        return None, True
    out = "".join(rewriter.out)
    if not out.strip():
        return None, True
    return out, True


class _FormDetector(HTMLParser):
    """Independent check for a live form in the OUTPUT."""

    def __init__(self):
        HTMLParser.__init__(self, convert_charrefs=False)
        self.found = False

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "form":
            self.found = True

    handle_startendtag = handle_starttag


def looks_interactive(html):
    """True when a rewritten page still contains something that could submit.

    Used as a refusal check, not a warning: a page that survives rewriting with
    a live form is a bug here, and publishing it would put a working-looking
    post box in front of somebody during an outage.

    PARSED, not substring-matched. A `<form>` written inside an HTML comment is
    inert, and a naive search calls it a form — which would drop a perfectly
    good page from every snapshot forever, with a message blaming the rewriter.
    That is not hypothetical: it is what the first version of this did, and the
    comment case is exactly the reason the rewriter itself is not a regex.
    """
    detector = _FormDetector()
    try:
        detector.feed(html or "")
        detector.close()
    except Exception:
        # Unparseable output is not something to publish either way.
        return True
    return detector.found
