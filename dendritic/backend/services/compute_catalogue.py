"""What the network can be asked to run: the site's copy of the catalogue.

WHY THIS IS A HAND-MAINTAINED MIRROR
------------------------------------
There is NO shared schema between this file and the node. The node's tables
(`catalogueImages` in cmd/syndichan-node/computeapi.go for languages, and
`Workloads` in internal/compute/catalogue.go for workloads) are the authority on
what actually exists, and this is the site's copy of them, retyped by hand. That
is a real duplication and it is deliberate: the alternative is the site fetching
a capability document from a node before it can render a form, which makes the
submit page depend on a volunteer being awake.

The duplication is defended by a TEST rather than by discipline —
tests/test_compute_catalogue.py reads the node's Go source and the
compute-images/ directory and fails when the two lists drift. A name offered
here with no image behind it is a promise made at the exact moment somebody
commits to it, and broken at dispatch.

WORKLOAD IS NOT LANGUAGE
------------------------
A LANGUAGE job carries a program: the submitter names an entry point and the
image runs it. That is arbitrary code by any honest reading, which is why it is
gated on hardware isolation.

A WORKLOAD job carries only DATA. The image is fixed at build time, the
submitter supplies an input file and nothing else, and there is no entry point
to name because there is nothing to choose. That is what makes a workload
deployable on volunteer hardware under the catalogue rule today, while the
language images wait for microVMs.

So they are two different fields, not two values of one field. Collapsing them
("just add 'embed' to the language list") would mean the isolation rule had to
be re-derived from a name at every point that reads it.
"""

# Workloads: fixed images that take data and produce a file.
#
# Keys mirror the node's workload table. `input_file` and `output_file` are the
# names INSIDE the container's /work, and they are part of the contract with the
# image — embed.py reads /work/input.jsonl and writes /work/output.jsonl by
# those literal names, so the site validating against anything else would accept
# a job that could only fail on the node.
WORKLOADS = {
    "embed": {
        "label": "Text embeddings",
        "input_file": "input.jsonl",
        "output_file": "output.jsonl",
        # The image, the file it is published as, and the hash of that file.
        #
        # WHY THE SITE CARRIES A DIGEST IT DOES NOT ENFORCE
        # -------------------------------------------------
        # The node enforces it, from a copy compiled into its own binary, and
        # that is the whole security argument — a digest served alongside the
        # bytes proves only that the two agree. So what is this copy for?
        #
        # It is what makes the PUBLISH step checkable. scripts/
        # publish_compute_images.py refuses to store a tarball whose hash is not
        # this one, so the bytes at /dl/compute-embed.tar and the bytes every
        # node was built to accept cannot drift apart silently: the publish
        # fails, here, instead of a fleet of nodes quietly refusing an artifact
        # nobody realises is wrong.
        #
        # tests/test_compute_catalogue.py reads the node's Go table and fails
        # when these three disagree with it, for the same reason it already does
        # so for the file names.
        "image": "registry.local/compute-embed:latest",
        "image_artifact": "compute-embed.tar",
        "image_digest": "a5643d5a718f18697b3847616f122ded7bdd063d45751439a4412215d4fd65f7",
        # No entry point: the image IS the workload. A submitter has nothing to
        # name, so being asked for a name would be a question with one answer.
        "needs_entrypoint": False,
        # Bit-reproducible: pinned model, single-threaded inference, hex-encoded
        # float32 output. This is what lets M5 verify it by hash equality
        # instead of by tolerance, and it is why this is M10's first slice.
        "deterministic": True,
        "device": "cpu",
        # Verified EVERY time, unlike the 0.25 sampling a rental gets. A replica
        # of this costs one node a few seconds of CPU, and the whole point of
        # picking a bit-exact workload first was to be able to afford that.
        "default_verify_rate": 1.0,
        "blurb": ("One JSON object per line with an \"id\" and a \"text\"; each "
                  "line comes back as a normalised 384-dimension vector. The "
                  "model is pinned and the run is single-threaded, so two nodes "
                  "given the same input produce byte-identical output — which "
                  "is what makes the result checkable rather than merely "
                  "plausible."),
    },
}

# Languages the NODE has images for. Not the same list as
# services/code_runner.LANGUAGES, and deliberately not shared with it: that one
# governs the LOCAL javascript/python judge pod, a different runner with a
# different set of images. Merging them would offer "javascript" to the network
# (no image, fails at dispatch) and hide "c" and "go" from the arcade judge.
LANGUAGES = ("python", "go", "c")


def is_workload(name):
    """Whether `name` is a catalogue workload."""
    return bool(name) and str(name) in WORKLOADS


def workload(name):
    """The workload spec, or None. Callers branch on None rather than KeyError."""
    if not name:
        return None
    return WORKLOADS.get(str(name))


def remote_languages():
    """Languages that can be dispatched to a volunteer node."""
    return tuple(LANGUAGES)


def workload_names():
    """Catalogue workloads, in a stable order for a form."""
    return tuple(sorted(WORKLOADS))


def input_file(name):
    """The one file a workload job must carry, or None."""
    spec = workload(name)
    return spec.get("input_file") if spec else None


def output_file(name):
    """The file the image produces, or None."""
    spec = workload(name)
    return spec.get("output_file") if spec else None


def image_artifact(name):
    """The published file that carries this workload's image, or None."""
    spec = workload(name)
    return spec.get("image_artifact") if spec else None


def image_digest(name):
    """The SHA-256 the node will demand of that file, or None."""
    spec = workload(name)
    return spec.get("image_digest") if spec else None


def artifact_workload(artifact):
    """Which workload a published artifact name belongs to, or None.

    Used by /dl/ to answer for a filename without letting the filename choose
    the object: the name is matched against this closed table and the digest
    comes from the release index, exactly the way a platform key does for a
    binary. A name not in the table is a 404, never a lookup.
    """
    if not artifact:
        return None
    for name, spec in WORKLOADS.items():
        if spec.get("image_artifact") == artifact:
            return name
    return None


def default_verify_rate(name, fallback=0.25):
    """How often to spend a replica on this workload.

    Falls back to the rental sampling rate for anything not in the table, so a
    caller that mistypes a name over-verifies rather than silently trusting.
    """
    spec = workload(name)
    if not spec:
        return fallback
    return float(spec.get("default_verify_rate", fallback))


def as_json():
    """The catalogue, for a submit page."""
    return {
        "languages": list(LANGUAGES),
        "workloads": [
            dict(name=name, **{k: v for k, v in spec.items()})
            for name, spec in sorted(WORKLOADS.items())
        ],
    }
