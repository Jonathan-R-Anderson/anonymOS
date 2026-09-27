#!/usr/bin/env python3
"""S13 — the anonymity-claim checker. P13's T13.5 and E13.3.

Constitution S13 forbids four words in shipped documentation, and §25(c) forbids
an anonymity claim without a stated adversary and a stated bound. The reason is
not tone. A user who reads "untraceable" and acts on it takes a risk the system
does not carry, and the difference between "anonymous" and "anonymous against a
partial observer who does not control your guard" is the entire engineering
content of Parts I-IV.

Two rules, and the second is the one that does the work:

  BANNED     the four S13 words, plus their obvious neighbours. Absolute
             language about a probabilistic system is wrong however it is
             phrased.

  UNSCOPED   an anonymity claim with no adversary and no bound nearby. This is
             where real documentation fails: not "untraceable" but "your traffic
             is anonymous", full stop, which is false against a global passive
             adversary and §16.5 says so.

Exit status is 0 when clean, 1 when a violation is found, so a documentation
build can depend on it.

    python3 roadmap/check-claims.py [path ...]

With no arguments it checks the shipped documentation set below. The ROADMAP IS
NOT IN THAT SET, deliberately: it is an engineering document whose job is to
discuss these very claims, quote the banned words in order to forbid them, and
record where the system fails. A checker that could not tell a specification
from a user-facing page would push the honest discussion out of the tree, which
is the opposite of what S13 wants.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# What ships to a reader who is deciding whether to trust the system.
# The node docs are here because they ship with the binary. The WEBSITE is here
# because it is what a user reads before deciding to trust the system, and it is
# the document most likely to acquire a claim nobody checked -- a front page is
# written to persuade, and S13 exists precisely for that pressure.
SHIPPED = [
    "dendritic-node/README.md",
    "dendritic-node/SECURITY.md",
    # The incident-response procedure is here for the same reason the website is.
    # An incident write-up is the document most likely to carry an unscoped
    # anonymity claim -- "users were not deanonymised" is the sentence everybody
    # reaches for on day one -- and a runbook that models the sentence it forbids
    # teaches it. Its own step 5 says to run this checker; it has to pass it.
    "dendritic-node/INCIDENT-RESPONSE.md",
    # The drill script for the same reason, plus one of its own: its record
    # sheet is filled in DURING an incident exercise, which is exactly when
    # somebody writes "no users were affected" without a stated adversary.
    "dendritic-node/INCIDENT-DRILL.md",
    "dendritic-node/DCS.md",
    "dendritic-node/GATEWAY.md",
    "backend/templates/react-index.html",
    "deploy-configs/index-greeting.html",
]

# S13's four, plus the neighbours that mean the same thing.
BANNED = [
    (re.compile(r"\bperfect(ly)?\s+(anonym|privat|secur|unlinkab)", re.I),
     "S13: 'perfect' applied to an anonymity property"),
    (re.compile(r"\buntraceable\b", re.I), "S13: 'untraceable'"),
    (re.compile(r"\bunbreakable\b", re.I), "S13: 'unbreakable'"),
    (re.compile(r"\bimpossible\s+to\s+(block|trace|break|censor)\b", re.I),
     "S13: 'impossible to block/trace/break/censor'"),
    (re.compile(r"\bcompletely\s+(anonymous|private|secure)\b", re.I),
     "S13: 'completely' applied to an anonymity property"),
    (re.compile(r"\b(guarantee[sd]?|ensures?)\s+(your\s+)?(anonymity|privacy)\b", re.I),
     "S13: a guarantee of anonymity"),
    (re.compile(r"\bno\s+one\s+can\s+(see|trace|track|link)\b", re.I),
     "S13: an absolute claim about what an observer cannot do"),
]

# A claim of anonymity...
CLAIM = re.compile(
    r"\b(anonymous|anonymity|unlinkab\w+|untrackable|private\s+by\s+design)\b", re.I)

# ...is scoped if an adversary or a bound is stated within the same block.
#
# The last two alternatives were added after the first run flagged two blocks on
# the front page that were ALREADY doing the right thing: "No single relay learns
# both ends" states an adversary class, and "it only protects you when it is
# ordinary" states a condition. A checker that rejects correct scoping teaches
# authors to delete the scoping, which is the failure this whole check exists to
# prevent -- so the pattern was widened rather than the copy weakened.
SCOPE = re.compile(
    r"\b(adversar\w+|threat\s+model|observer|against\b|assum\w+|bound\w*|"
    r"probabilit\w+|does\s+not\s+(hide|defend|protect)|limit\w*|"
    r"partial|global\s+passive|correlat\w+|unsolved|not\s+claim\w*|"
    r"see\s+SECURITY|§|section\s+\d|"
    r"no\s+single\s+\w+|only\s+.{0,60}?\bwhen\b)", re.I)


# Things that are not prose and must not be scanned as prose.
FENCE = re.compile(r"```")
SCRIPT = re.compile(r"(?is)<(script|style)\b.*?</\1>")
HTML_COMMENT = re.compile(r"(?s)<!--.*?-->")
JINJA_COMMENT = re.compile(r"(?s)\{#.*?#\}")
JINJA_TAG = re.compile(r"(?s)\{%.*?%\}")
TAG = re.compile(r"(?s)<[^>]+>")


def blank_out(pattern, text):
    """Replace matches with newline-preserving blanks, so line numbers hold."""
    def repl(m):
        return re.sub(r"[^\n]", " ", m.group(0))
    return pattern.sub(repl, text)


def paragraphs(text, html):
    """Yield (line number of the paragraph's first line, paragraph text).

    Blocks are separated by blank lines in Markdown. In HTML there are often no
    blank lines at all, so tags are blanked out FIRST -- preserving newlines so
    reported line numbers still point at the source -- and the resulting runs of
    text become the paragraphs. Without this an entire template is one
    "paragraph", any scoping word anywhere in the file excuses every claim in
    it, and the check passes vacuously.
    """
    if html:
        for pat in (SCRIPT, HTML_COMMENT, JINJA_COMMENT, JINJA_TAG):
            text = blank_out(pat, text)
        text = blank_out(TAG, text)

    lines = text.split("\n")
    in_fence = False
    buf, start = [], 1
    for i, line in enumerate(lines, 1):
        if not html and FENCE.match(line.lstrip()):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if line.strip() == "":
            if buf:
                yield start, "\n".join(buf)
                buf = []
            start = i + 1
            continue
        if not buf:
            start = i
        buf.append(line)
    if buf:
        yield start, "\n".join(buf)


def check(path):
    findings = []
    try:
        text = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        return [(path, 0, "listed in SHIPPED but not present")]

    html = Path(path).suffix.lower() in (".html", ".htm", ".jinja", ".j2")

    def at(start, para, m):
        """Line of the MATCH, not of the paragraph it sits in."""
        return start + para[:m.start()].count("\n")

    for lineno, para in paragraphs(text, html):
        for pattern, why in BANNED:
            m = pattern.search(para)
            if m:
                findings.append((path, at(lineno, para, m), f"{why}: {m.group(0)!r}"))
        m = CLAIM.search(para)
        if m and not SCOPE.search(para):
            findings.append((path, at(lineno, para, m),
                             f"E13.3: unscoped anonymity claim {m.group(0)!r} -- "
                             f"no adversary, bound or limit stated in this block"))
    return findings


def main(argv):
    targets = argv[1:] or [str(ROOT / p) for p in SHIPPED]
    findings = []
    for t in targets:
        findings.extend(check(t))

    if not findings:
        print(f"S13: {len(targets)} document(s) clean")
        return 0
    for path, lineno, why in findings:
        rel = Path(path).resolve()
        try:
            rel = rel.relative_to(ROOT)
        except ValueError:
            pass
        print(f"{rel}:{lineno}: {why}")
    print(f"\nS13: {len(findings)} violation(s)")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
