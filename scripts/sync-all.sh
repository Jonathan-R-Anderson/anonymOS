#!/usr/bin/env bash
# Push HEAD to every place the project lives, and report what is where.
#
# There are three copies of this repo and they drift silently:
#   * this machine        — where the work happens
#   * the build server    — where it is compiled and booted (no compiler here)
#   * origin (GitHub)     — the durable copy
#
# Drift is not cosmetic.  The build server compiles whatever is in ITS working tree, and the
# build manifest baked into the ISO records ITS git HEAD.  So a server that is behind produces
# an image whose manifest names a commit that does not describe its contents — which defeats
# the whole point of the manifest, and is exactly the confusion track A exists to remove.
# (That happened: files were scp'd for speed, the server's HEAD stayed put, and `make verify`
# cheerfully reported "built from e0c421c32b (== HEAD)" for an image built from newer sources.)
#
# The build server has a CHECKED-OUT working tree, so it cannot be pushed to directly on the
# branch it has open.  Push to a side branch and fast-forward there instead.  A fast-forward
# leaves untracked build artifacts alone — deps/busybox alone carries ~580 modified files that
# must survive, or the next build is an hour longer.
#
# Usage:
#   scripts/sync-all.sh            # push everywhere, then report
#   scripts/sync-all.sh --status   # report only, push nothing
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BUILD_HOST="${BUILD_HOST:-bruns@192.168.1.181}"
BUILD_PATH="${BUILD_PATH:-/home/bruns/Documents/anonymOS}"
SIDE_BRANCH="${SIDE_BRANCH:-from-nostromo}"
STATUS_ONLY=0
[ "${1:-}" = "--status" ] && STATUS_ONLY=1

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
HEAD_SHA="$(git rev-parse --short=10 HEAD)"

dirty="$(git status --porcelain | wc -l)"
if [ "$dirty" -ne 0 ]; then
    echo "sync-all: WARNING — $dirty uncommitted change(s) here; only committed work syncs"
fi

if [ "$STATUS_ONLY" -eq 0 ]; then
    echo "sync-all: pushing $BRANCH ($HEAD_SHA)"

    if git remote get-url origin >/dev/null 2>&1; then
        if git push origin "$BRANCH" 2>&1 | sed 's/^/  origin: /'; then :; else
            echo "  origin: PUSH FAILED" >&2
        fi
    fi

    if git remote get-url buildserver >/dev/null 2>&1; then
        git push -q buildserver "HEAD:refs/heads/$SIDE_BRANCH" 2>&1 | sed 's/^/  build : /'
        # --ff-only so a divergent server is reported rather than silently merged.  It also
        # refuses when a tracked file it must update is locally modified, which is the correct
        # outcome: that means someone edited the server's tree directly and it needs a look.
        ssh -o BatchMode=yes "$BUILD_HOST" \
            "cd '$BUILD_PATH' && git merge --ff-only '$SIDE_BRANCH' >/dev/null 2>&1 \
             && echo '  build : fast-forwarded' \
             || echo '  build : MERGE REFUSED (diverged, or its tree has local edits)'"
    fi
    echo
fi

echo "sync-all: where everything is"
printf '  %-14s %s\n' "local" "$(git log --oneline -1 | cut -c1-72)"
if git remote get-url origin >/dev/null 2>&1; then
    git fetch -q origin 2>/dev/null || true
    printf '  %-14s %s\n' "origin" "$(git log --oneline -1 "origin/$BRANCH" 2>/dev/null | cut -c1-72)"
    ahead="$(git rev-list --count "origin/$BRANCH..HEAD" 2>/dev/null || echo '?')"
    [ "$ahead" != "0" ] && printf '  %-14s %s\n' "" "^ local is $ahead commit(s) ahead of origin"
fi
srv="$(ssh -o BatchMode=yes -o ConnectTimeout=8 "$BUILD_HOST" \
        "cd '$BUILD_PATH' && git log --oneline -1" 2>/dev/null | cut -c1-72)"
printf '  %-14s %s\n' "build server" "${srv:-unreachable}"
