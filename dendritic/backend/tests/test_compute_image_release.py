"""Publishing a catalogue image: the ways it could hand a node the wrong bytes.

This is the second feature on the site that ends with somebody executing
something on their own machine, and it is the worse of the two: the node loads
the file into a root container daemon without a human present. The node's own
defence is a SHA-256 compiled into its binary, and that defence is only useful
if the thing published at /dl/ is the thing the fleet was built to accept.

So these are about the publish step refusing, loudly, at the one moment a person
is standing there: a rebuilt image whose hash nobody propagated, a file that is
not an image at all, and an archive saved from the wrong image.

Loaded with `shared`, the object store and SiteSetting stubbed, so none of this
needs a database. The CATALOGUE is the real one — the declared digest is exactly
what is under test, and a fake of it would test the fake.
"""

import hashlib
import importlib.util
import io
import json
import os
import sys
import tarfile
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

WORKLOAD = "embed"


class FakeLogger(object):
    def __init__(self):
        self.messages = []

    def _record(self, *args, **_kwargs):
        self.messages.append(str(args[0]) if args else "")

    info = warning = error = debug = exception = _record

    def said(self, fragment):
        return any(fragment in message for message in self.messages)


class FakeApp(object):
    def __init__(self):
        self.logger = FakeLogger()
        self.config = {}


class FakeSession(object):
    def __init__(self):
        self.commits = 0

    def commit(self):
        self.commits += 1

    def rollback(self):
        pass


class FakeDB(object):
    def __init__(self):
        self.session = FakeSession()


class FakeStore(object):
    """An object store that remembers what it was told to keep."""

    def __init__(self):
        self.objects = {}
        self.buckets = set()

    def head_bucket(self, Bucket):
        if Bucket not in self.buckets:
            raise KeyError(Bucket)

    def create_bucket(self, Bucket):
        self.buckets.add(Bucket)

    def put_object(self, Bucket, Key, Body):
        self.objects[Key] = bytes(Body)

    def get_object(self, Bucket, Key):
        if Key not in self.objects:
            raise KeyError(Key)
        return {"Body": io.BytesIO(self.objects[Key])}


SETTINGS = {}
STORE = FakeStore()
APP = FakeApp()
DB = FakeDB()


def _install_stubs():
    shared = types.ModuleType("shared")
    shared.app = APP
    shared.db = DB
    sys.modules["shared"] = shared

    site_setting = types.ModuleType("model.SiteSetting")
    site_setting.get_setting = lambda key, default="": SETTINGS.get(key, default)

    def _set(key, value):
        SETTINGS[key] = value

    site_setting.set_setting = _set
    sys.modules.setdefault("model", types.ModuleType("model"))
    sys.modules["model.SiteSetting"] = site_setting

    snapshot = types.ModuleType("services.snapshot_dht")
    snapshot._client = lambda: STORE
    sys.modules["services.snapshot_dht"] = snapshot


_SAVED = {}


def setUpModule():
    for name in ("shared", "model.SiteSetting", "services.snapshot_dht"):
        _SAVED[name] = sys.modules.get(name)
    _install_stubs()
    global release
    spec = importlib.util.spec_from_file_location(
        "compute_image_release_under_test",
        os.path.join(BACKEND, "services", "compute_image_release.py"))
    release = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(release)


def tearDownModule():
    for name, module in _SAVED.items():
        if module is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = module


def save_archive(repo_tags, extra_bytes=b""):
    """A tar shaped like `docker save` output.

    Modelled on the real thing rather than invented: a save of alpine:3.19 on
    Docker 29.4.2 contains blobs/sha256/<hex> entries, index.json,
    manifest.json and oci-layout, with manifest.json carrying
    [{"Config": ..., "RepoTags": [...], "Layers": [...]}].
    """
    manifest = json.dumps([{
        "Config": "blobs/sha256/" + "0" * 64,
        "RepoTags": list(repo_tags),
        "Layers": ["blobs/sha256/" + "1" * 64],
    }]).encode("utf-8")
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, body in (("blobs/sha256/" + "1" * 64, b"layer" + extra_bytes),
                           ("index.json", b'{"schemaVersion":2}'),
                           ("manifest.json", manifest),
                           ("oci-layout", b'{"imageLayoutVersion":"1.0.0"}')):
            info = tarfile.TarInfo(name)
            info.size = len(body)
            archive.addfile(info, io.BytesIO(body))
    return buffer.getvalue()


def reset():
    SETTINGS.clear()
    STORE.objects.clear()
    STORE.buckets.clear()
    APP.logger.messages = []
    DB.session.commits = 0


class SniffingTest(unittest.TestCase):
    """Asking the file what it is, the way a binary is asked its platform."""

    def test_a_save_archive_is_recognised(self):
        self.assertTrue(release.looks_like_image_archive(save_archive(["a:b"])))

    def test_something_that_is_not_an_archive_is_not(self):
        for body in (b"", b"short", b"\x00" * 4096, b"x" * 4096,
                     json.dumps({"not": "a tar"}).encode() * 100):
            self.assertFalse(release.looks_like_image_archive(body))

    def test_a_plain_tar_without_the_markers_is_not_an_image(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            info = tarfile.TarInfo("hello.txt")
            info.size = 5
            archive.addfile(info, io.BytesIO(b"hello"))
        self.assertFalse(release.looks_like_image_archive(buffer.getvalue()))

    def test_the_repo_tags_are_read_out_of_the_manifest(self):
        body = save_archive(["registry.local/compute-embed:latest"])
        self.assertEqual(release.archive_repo_tags(body),
                         ["registry.local/compute-embed:latest"])

    def test_no_manifest_means_no_tags_rather_than_an_exception(self):
        self.assertEqual(release.archive_repo_tags(b"nonsense" * 500), [])


class PublishRefusalTest(unittest.TestCase):
    """The three refusals. Each one is a fleet-wide outage if it does not fire.

    Note what these do NOT do: construct an archive matching the declared
    digest. That digest is of a real 186 MB image and no test can reproduce it,
    so the happy-path class below points the declared value at bytes it made
    instead. Said here so the absence reads as a decision rather than a gap.
    """

    def setUp(self):
        reset()
        from services import compute_catalogue

        self.declared = compute_catalogue.image_digest(WORKLOAD)
        self.tag = compute_catalogue.workload(WORKLOAD)["image"]

    def test_a_rebuilt_image_whose_hash_nobody_propagated_is_refused(self):
        """THE defect this exists to catch.

        Every node checks a downloaded image against a digest compiled into its
        own binary. Publishing bytes that do not match it publishes something
        the whole fleet refuses — and the symptom is not an error here, it is
        compute capacity going to zero for a reason visible only in volunteers'
        journals.
        """
        body = save_archive([self.tag], extra_bytes=b"a rebuild")
        self.assertNotEqual(hashlib.sha256(body).hexdigest(), self.declared)

        self.assertIsNone(release.publish(WORKLOAD, body))
        self.assertEqual(STORE.objects, {},
                         "bytes the fleet will refuse were stored anyway")
        self.assertEqual(SETTINGS, {}, "the index was moved to an unusable artifact")
        self.assertTrue(APP.logger.said("the catalogue declares"),
                        "the refusal did not say what was expected: %s"
                        % APP.logger.messages)

    def test_a_file_that_is_not_an_image_is_refused(self):
        self.assertIsNone(release.publish(WORKLOAD, b"not a docker save" * 100))
        self.assertEqual(STORE.objects, {})
        self.assertTrue(APP.logger.said("not a docker save archive"))

    def test_an_archive_saved_from_the_wrong_image_is_refused(self):
        """`docker load` installs whatever tags the tarball declares.

        A verified artifact carrying the wrong tag loads perfectly and leaves the
        image still missing, so the node reports it cannot run the catalogue and
        stops advertising compute — with nothing at all wrong at this end.
        """
        body = save_archive(["registry.local/compute-python:latest"])
        self.assertIsNone(release.publish(WORKLOAD, body))
        self.assertEqual(STORE.objects, {})
        self.assertTrue(APP.logger.said("the archive carries"))

    def test_an_unknown_workload_is_refused(self):
        self.assertIsNone(release.publish("nope", save_archive(["x:y"])))
        self.assertEqual(STORE.objects, {})


class PublishHappyPathTest(unittest.TestCase):
    """What a correct publish leaves behind."""

    def setUp(self):
        reset()
        from services import compute_catalogue

        self.catalogue = compute_catalogue
        self.spec = compute_catalogue.WORKLOADS[WORKLOAD]
        self.saved_digest = self.spec["image_digest"]
        self.body = save_archive([self.spec["image"]])
        self.digest = hashlib.sha256(self.body).hexdigest()
        # The declared digest is of the real 186 MB image, which no test can
        # produce. Pointed at these bytes for the duration, and put back after.
        self.spec["image_digest"] = self.digest

    def tearDown(self):
        self.spec["image_digest"] = self.saved_digest

    def test_the_object_key_is_the_hash(self):
        entry = release.publish(WORKLOAD, self.body, version="test")
        self.assertIsNotNone(entry)
        self.assertEqual(list(STORE.objects), [self.digest],
                         "the store is content-addressed; the key must BE the hash")
        self.assertEqual(STORE.objects[self.digest], self.body)

    def test_the_index_records_what_a_node_needs_to_fetch_it(self):
        entry = release.publish(WORKLOAD, self.body)
        self.assertEqual(entry["sha256"], self.digest)
        self.assertEqual(entry["size"], len(self.body))
        self.assertEqual(entry["artifact"], self.spec["image_artifact"])
        self.assertEqual(entry["image"], self.spec["image"])
        recorded = json.loads(SETTINGS[release.SETTING_IMAGES])
        self.assertEqual(recorded[WORKLOAD]["sha256"], self.digest)
        self.assertEqual(DB.session.commits, 1)

    def test_bytes_that_do_not_read_back_are_not_indexed(self):
        # A hash announced for bytes that are not retrievable sends every
        # compute node to a download that does not exist, and they all stop
        # advertising. Publishing the index is the LAST step for that reason.
        original = STORE.get_object
        STORE.get_object = lambda Bucket, Key: {"Body": io.BytesIO(b"different")}
        try:
            self.assertIsNone(release.publish(WORKLOAD, self.body))
        finally:
            STORE.get_object = original
        self.assertEqual(SETTINGS, {})


class StreamTest(unittest.TestCase):
    def setUp(self):
        reset()

    def test_a_non_hex_key_is_refused_before_the_store_is_touched(self):
        for bad in ("", None, "../../etc/passwd", "sha256:" + "a" * 64, "A" * 64):
            self.assertIsNone(release.stream(bad))

    def test_the_body_comes_back_in_chunks(self):
        body = b"x" * 5000
        digest = hashlib.sha256(body).hexdigest()
        STORE.objects[digest] = body
        chunks = list(release.stream(digest, chunk_bytes=1024))
        self.assertEqual(b"".join(chunks), body)
        self.assertGreater(len(chunks), 1,
                           "a 186 MB artifact must not be materialised whole")

    def test_a_missing_object_is_none_rather_than_an_exception(self):
        self.assertIsNone(release.stream("b" * 64))


if __name__ == "__main__":
    unittest.main()
