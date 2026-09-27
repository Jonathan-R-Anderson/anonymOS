#!/bin/sh
# Runs the embedding workload. Takes no entrypoint.
#
# UNLIKE THE LANGUAGE IMAGES, this one runs fixed code. python/c/go execute a
# submitted program and are gated on M2 for exactly that reason; this image
# accepts DATA and runs only what was baked in at build time. That is what makes
# it deployable today under the catalogue rule rather than after arbitrary-code
# execution is defensible.
set -eu

# /work MUST be writable by uid 10001. The image runs unprivileged and writes
# output.jsonl there; a /work mounted root-owned or host-user-owned fails with
# EACCES at the very END of the job, after the model has loaded and every
# embedding has been computed. Checked here so the failure names its cause
# instead of surfacing as a Python traceback from the last line of the run.
if [ ! -w /work ]; then
    # Exit 2 == plumbing, the same code embed.py uses for a missing input file.
    # Both mean "the runner did not set the job up", which is a different thing
    # to answer than "the submitter's data is wrong" (3 and 4).
    echo "/work is not writable by uid $(id -u); the runner must mount it writable" >&2
    exit 2
fi

# $ENTRYPOINT is IGNORED here, deliberately: the image IS the workload, so there
# is nothing for a submitter to name. Sent one anyway, it changes nothing.
exec python3 /usr/local/bin/embed.py
