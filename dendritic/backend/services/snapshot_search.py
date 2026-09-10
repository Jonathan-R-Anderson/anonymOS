"""A search index small enough to ship inside the snapshot.

During an outage the search box is one of the first things a reader tries, and a
dead search box on an otherwise-working page reads as a broken site. So the
index travels with the snapshot, is content-addressed like everything else, and
is searched in the reader's browser — no origin, no gateway query, no server.

WHY A WORD INDEX AND NOT A SEARCH ENGINE
----------------------------------------
The roadmap offers SQLite, Tantivy, Meilisearch. Every one of them would be a
new dependency, a new build step, and a new binary format for a browser to
parse — to search a few hundred pages that are already sitting in the same
snapshot.

What is actually needed is: given a word, which frozen pages contain it. That is
an inverted index, it is a JSON object, and a browser can search it with no
library at all. When the corpus is large enough for that to hurt, the shape here
(one signed object named in the manifest) is unchanged — only the encoding
inside it would be.

WHAT IT DELIBERATELY DOES NOT DO
--------------------------------
No ranking, no stemming, no fuzzy matching. Emergency search should find the
page somebody knows exists, not compete with the live search. Pretending
otherwise would produce results a reader trusts and should not: the index covers
one frozen snapshot, so anything posted since is simply absent, and a confident
ranking over an incomplete corpus is worse than an obviously partial list.
"""

import re

# Deliberately generous: an index that misses a word is a reader who concludes
# the page is gone.
_WORD = re.compile(r"[a-z0-9][a-z0-9'-]{1,31}")

# Words in essentially every document carry no information and would dominate
# the index by size.
_STOPWORDS = frozenset("""
a an and are as at be but by for from has have if in into is it its of on or
that the their there these they this to was were what when where which who
will with you your
""".split())

# One page may contribute at most this many distinct words. A pathological page
# — a dictionary dump, a wordlist someone pasted — must not be able to inflate
# the snapshot every reader downloads.
MAX_WORDS_PER_PAGE = 400
# And the whole index is bounded, for the same reason.
MAX_INDEX_WORDS = 20000

_TAG = re.compile(r"<[^>]+>")
_SCRIPT = re.compile(r"<(script|style)\b.*?</\1>", re.IGNORECASE | re.DOTALL)


def text_of(html):
    """Visible text from a page, roughly.

    Scripts and styles are removed first: indexing a stylesheet's contents would
    fill the index with selector fragments that no reader will ever search for.
    """
    without_code = _SCRIPT.sub(" ", html or "")
    return _TAG.sub(" ", without_code)


def words_in(html):
    """Distinct indexable words on one page, bounded."""
    found = []
    seen = set()
    for match in _WORD.finditer(text_of(html).lower()):
        word = match.group(0)
        if word in _STOPWORDS or word in seen:
            continue
        seen.add(word)
        found.append(word)
        if len(found) >= MAX_WORDS_PER_PAGE:
            break
    return found


def build_index(pages, titles=None):
    """Build the inverted index. ``pages`` maps route -> rendered HTML.

    Routes are stored once in a list and referenced by position. A route repeated
    under every word it contains would make the index several times larger than
    the pages it describes, which for a file every reader downloads is the
    difference between useful and not.
    """
    titles = titles or {}
    routes = sorted(pages)
    position = {route: index for index, route in enumerate(routes)}
    index = {}
    for route in routes:
        for word in words_in(pages[route]):
            bucket = index.setdefault(word, [])
            if len(index) > MAX_INDEX_WORDS:
                break
            bucket.append(position[route])
    # Trim to a bounded, deterministic set: sorted so the same corpus always
    # produces the same bytes, which is what lets the index be content-addressed
    # and deduplicated between snapshots like every other object.
    words = sorted(index)[:MAX_INDEX_WORDS]
    return {
        "schema": 1,
        "routes": routes,
        "titles": [titles.get(route, route) for route in routes],
        "index": {word: sorted(set(index[word])) for word in words},
        "note": "Covers one frozen snapshot. Anything posted since is absent.",
    }


def title_of(html):
    """A page's <title>, for showing a result."""
    match = re.search(r"<title[^>]*>(.*?)</title>", html or "",
                      re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return _TAG.sub("", match.group(1)).strip()[:120]
