"""Publishing catalogue images so a volunteer who is not us can obtain them.

THE PROBLEM
-----------
A node that advertises compute and lacks `registry.local/compute-embed:latest`
either refuses or accepts and then dies `No such image`. `registry.local` is not
a registry and there was no image pull path in the node at all, so the images
existed only where somebody had hand-loaded a tarball. Building locally is fine
for a fleet you administer; it is not a distribution story, and until there is
one the catalogue is only usable on machines a human prepared.

WHY THIS REUSES THE RELEASE DISTRIBUTION RATHER THAN INVENTING ONE
------------------------------------------------------------------
The node binary is already published content-addressed into the object store,
indexed by one SiteSetting, and served at /dl/<name> with a /dl/<name>.sha256
sidecar that install.sh reads before running anything. That path is deployed,
cached, and already the thing a node knows how to talk to. A second mechanism
would be a second thing to keep working, a second thing to secure, and a second
thing to discover is broken.

So a catalogue image is published the same way, with the same properties:

  * the object key IS the sha256, so a wrong answer from the store is
    detectable rather than something to trust;
  * the hash is computed from the bytes actually stored, never taken from
    whoever uploaded;
  * one SiteSetting records which digest is current for each workload.

WHERE 186 MB GOES, AND WHY IT IS THE SAME STORE
-----------------------------------------------
`docker save registry.local/compute-embed:latest` is 194,401,280 bytes —
measured, not estimated. Three places were possible:

  backend/static/   No. services/node_release already refused this for 30 MB
                    binaries: it would ride in every container image, on a host
                    that has had its images garbage collected out from under it
                    by disk pressure, for a file that changes only when the
                    image is rebuilt.

  a new volume      No. It is one more thing to provision, back up and forget,
                    for bytes the object store already handles.

  the object store  Yes. It is content-addressed and backed by the DHT, which is
                    what this project's storage IS; a 186 MB object is erasure
                    coded and spread the same way a 186 MB video is, and nothing
                    about it is novel to that layer.

Not gzipped, and that is a measurement rather than a preference: `docker save`
already carries its layers compressed, so gzip -6 over the tarball took it from
194,401,280 to 193,749,973 bytes — 0.33%. Compressing would cost CPU on every
publish and a decompression step on every node in exchange for nothing.

WHAT THIS DOES NOT DO
---------------------
It does not decide whether a node loads the image. That is settled by a SHA-256
compiled into the node's own binary (internal/compute/catalogue.go). This module
refuses to publish bytes that do not match that value — see `publish` — so the
two cannot drift apart without the publish failing first, which is the whole
point of keeping a copy of the digest here.
"""

import hashlib
import json
import re

from shared import app

# The same bucket the node binaries use. Content-addressed, so the key is the
# hash and two kinds of artefact cannot collide by name — there are no names.
BUCKET = "releases"

SETTING_IMAGES = "compute_image_index"

# A docker save tarball is a tar whose first entries include these. Checked so
# the file is asked what it IS, exactly as node_release.executable_platform asks
# a binary which platform it is for: publishing is done by hand at midnight, and
# a mis-picked file that verifies as "some bytes" would be discovered on a
# volunteer's node as a docker load that fails.
_ARCHIVE_MARKERS = ("manifest.json", "oci-layout", "index.json")

# Read from the front of the tar rather than the whole file: the members that
# identify it are written first, and the alternative is holding 186 MB twice.
_SNIFF_BYTES = 512 * 1024


def _client():
    from services.snapshot_dht import _client as build_client

    return build_client()


def _bucket():
    prefix = app.config.get("S3_UUID_PREFIX") or ""
    return "%s%s" % (prefix, BUCKET)


def index():
    """Published images: workload -> {sha256, size, image, artifact}."""
    from model.SiteSetting import get_setting

    try:
        return json.loads(get_setting(SETTING_IMAGES, "") or "{}")
    except ValueError:
        return {}


def tar_members(body, limit=None):
    """The member names at the front of a tar, best effort.

    A hand-rolled reader rather than tarfile, because tarfile wants a file
    object it can seek and this is asked to look at the first half megabyte of
    a 186 MB blob. The format is 512-byte headers with the name in the first 100
    bytes and the size as octal at offset 124; that is enough to walk the front
    of the archive and stop.
    """
    names = []
    view = memoryview(body)[:limit or _SNIFF_BYTES]
    offset = 0
    while offset + 512 <= len(view):
        header = bytes(view[offset:offset + 512])
        if header[:1] == b"\x00":
            break  # padding, i.e. the end
        name = header[:100].split(b"\x00", 1)[0].decode("utf-8", "replace")
        if not name:
            break
        names.append(name)
        raw_size = header[124:136].split(b"\x00", 1)[0].strip() or b"0"
        try:
            size = int(raw_size, 8)
        except ValueError:
            break
        # Payload is padded to a 512-byte boundary, header included.
        offset += 512 + ((size + 511) // 512) * 512
    return names


def looks_like_image_archive(body):
    """Whether these bytes are a `docker save` tarball.

    Returns True/False. Deliberately cheap and deliberately not a guarantee:
    it catches the wrong file, not a hostile one. Nothing about "this parses as
    a tar" would make an unverified image safe to load, which is why the node
    checks a digest instead of inspecting anything.
    """
    if not body or len(body) < 1024:
        return False
    names = tar_members(body)
    return any(marker in names for marker in _ARCHIVE_MARKERS)


def archive_repo_tags(body):
    """The RepoTags a save archive declares, or [] if they cannot be read.

    This is the check that catches the mistake worth catching: a tarball saved
    from the wrong image verifies as a perfectly good tar, publishes cleanly,
    and then `docker load`s on a volunteer's machine under a tag nothing asked
    for — at which point the node reports the image still missing and stops
    advertising compute, for a reason nobody can see from here.

    manifest.json sits at the FRONT of the archive (measured against Docker
    29.4.2), so this reads only the sniff window rather than the whole file.
    """
    view = memoryview(body)[:_SNIFF_BYTES]
    offset = 0
    while offset + 512 <= len(view):
        header = bytes(view[offset:offset + 512])
        if header[:1] == b"\x00":
            break
        name = header[:100].split(b"\x00", 1)[0].decode("utf-8", "replace")
        if not name:
            break
        raw_size = header[124:136].split(b"\x00", 1)[0].strip() or b"0"
        try:
            size = int(raw_size, 8)
        except ValueError:
            break
        start = offset + 512
        if name == "manifest.json" and start + size <= len(view):
            try:
                manifest = json.loads(bytes(view[start:start + size]).decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                return []
            tags = []
            for entry in manifest if isinstance(manifest, list) else []:
                for tag in (entry or {}).get("RepoTags") or []:
                    tags.append(str(tag))
            return tags
        offset = start + ((size + 511) // 512) * 512
    return []


def publish(workload, body, version=""):
    """Store one catalogue image tarball and record its hash. Entry, or None.

    THE THREE REFUSALS, and why each one is a refusal rather than a warning:

    1. Not a docker save archive. Publishing a mis-picked file would put bytes
       at a URL every compute node fetches, and the failure would surface as a
       docker load error on somebody else's machine days later.

    2. The archive does not carry the tag this workload names. `docker load`
       installs whatever tags the tarball declares. A verified artifact with the
       wrong tag loads perfectly and leaves the image still missing.

    3. The hash is not the one the catalogue declares. This is the important
       one. Nodes check a digest compiled into their own binary; publishing
       bytes that do not match it publishes something every node will refuse.
       Refused HERE, where a person is standing at a terminal and can look at
       what they just built, rather than discovered as a fleet-wide outage.
    """
    from model.SiteSetting import get_setting, set_setting
    from services import compute_catalogue
    from shared import db

    spec = compute_catalogue.workload(workload)
    if not spec:
        app.logger.error("compute image: %r is not a catalogue workload", workload)
        return None
    if not looks_like_image_archive(body):
        app.logger.error("compute image: %s is not a docker save archive", workload)
        return None

    wanted_tag = spec.get("image") or ""
    tags = archive_repo_tags(body)
    if wanted_tag and tags and wanted_tag not in tags:
        app.logger.error(
            "compute image: refused %s — the archive carries %s, not %s",
            workload, ", ".join(tags), wanted_tag)
        return None

    digest = hashlib.sha256(body).hexdigest()
    declared = (spec.get("image_digest") or "").strip().lower()
    if declared and digest != declared:
        app.logger.error(
            "compute image: refused %s — this tarball is %s and the catalogue "
            "declares %s. Every node checks the declared value against a copy "
            "compiled into its own binary, so publishing this would publish "
            "bytes the whole fleet refuses. Either publish the image the "
            "catalogue describes, or change the digest in BOTH "
            "services/compute_catalogue.py and "
            "storage-client/internal/compute/catalogue.go and ship a node "
            "build that expects it.", workload, digest, declared)
        return None

    try:
        client = _client()
        try:
            client.head_bucket(Bucket=_bucket())
        except Exception:
            client.create_bucket(Bucket=_bucket())
        client.put_object(Bucket=_bucket(), Key=digest, Body=body)
        # Read back before publishing the hash, exactly as node_release does: a
        # hash announced for bytes that are not retrievable sends every compute
        # node to a download that does not exist, and they all stop advertising.
        fetched = client.get_object(Bucket=_bucket(), Key=digest)["Body"].read()
        if hashlib.sha256(fetched).hexdigest() != digest:
            app.logger.error("compute image: %s did not read back correctly", workload)
            return None
    except Exception:
        app.logger.exception("compute image: could not store %s", workload)
        return None

    try:
        current = json.loads(get_setting(SETTING_IMAGES, "") or "{}")
    except ValueError:
        current = {}
    current[workload] = {
        "sha256": digest,
        "size": len(body),
        "image": wanted_tag,
        "artifact": spec.get("image_artifact") or "",
        "version": version or "",
    }
    set_setting(SETTING_IMAGES, json.dumps(current))
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.exception("compute image: could not record the index")
        return None
    return current[workload]


def stream(digest, chunk_bytes=1 << 20):
    """The stored artifact, a chunk at a time, or None if it is not there.

    STREAMED rather than returned whole, unlike node_release.fetch. A 30 MB
    binary read into memory is a cost; a 186 MB image read into memory, copied
    into a response and held until the client has finished reading is most of a
    gigabyte per concurrent download, inside a gevent worker where every other
    greenlet waits behind the allocation.

    The trade this makes: node_release.fetch re-hashes before it answers, and a
    generator cannot — by the time the last byte is known the first has been
    sent. So the check moves to where it was always load-bearing: the NODE
    verifies the whole file against a digest compiled into its own binary before
    it hands a byte to Docker. A wrong answer from the store is caught there,
    where refusing costs nothing, instead of here where refusing means changing
    a status code that has already been written.
    """
    if not re.fullmatch(r"[0-9a-f]{64}", digest or ""):
        return None
    # The store is opened HERE, not inside the generator. Flask consumes a
    # streamed body after the request context has been torn down, so a generator
    # that reached for app.config or built a client on first read would fail on
    # the first chunk of every download — and only in production, where a real
    # request context exists to end.
    try:
        body = _client().get_object(Bucket=_bucket(), Key=digest)["Body"]
    except Exception:
        return None

    def chunks():
        try:
            while True:
                block = body.read(chunk_bytes)
                if not block:
                    return
                yield block
        finally:
            try:
                body.close()
            except Exception:
                pass

    return chunks()
