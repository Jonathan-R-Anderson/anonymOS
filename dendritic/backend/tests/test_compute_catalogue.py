"""The catalogue the site offers must be the one the network can actually run.

services/compute_catalogue.py is a HAND-MAINTAINED mirror of the node's tables
and of compute-images/. There is no shared schema between a Python service and a
Go binary, so nothing but a test stops the two drifting — and the drift is not
harmless: a name offered on the submit page with no image behind it is a promise
made at the exact moment somebody commits to it and broken at dispatch, after
they have waited in a queue.

So these read the OTHER side rather than a copy of it: the Go source for the
languages, the image directories for the workloads.
"""

import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
ROOT = os.path.dirname(BACKEND)
IMAGES = os.path.join(ROOT, "compute-images")
# The node tree was RENAMED storage-client -> dendritic-node. These paths
# were not followed, so all 14 tests here failed on a missing directory and
# read as orphans of a deleted feature -- item 4.13 counted them as such. They
# are not orphans: the catalogue they compare against is still there, and
# nothing else compares the two catalogues.
NODE = os.path.join(ROOT, "dendritic-node", "cmd", "syndichan-node")
NODE_CATALOGUE = os.path.join(ROOT, "dendritic-node", "internal", "compute",
                              "catalogue.go")

import sys

if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from services import compute_catalogue as catalogue  # noqa: E402


def _node_catalogue_images():
    """The keys of catalogueImages, read out of the node's Go source.

    Parsed rather than duplicated. A test that carried its own copy of the list
    would keep passing after somebody added a language to the node and forgot
    the site, which is the entire failure this file exists to catch.
    """
    found = {}
    for name in sorted(os.listdir(NODE)):
        if not name.endswith(".go"):
            continue
        with open(os.path.join(NODE, name), encoding="utf-8") as handle:
            source = handle.read()
        match = re.search(r"catalogueImages\s*=\s*map\[string\]string\s*\{(.*?)\n\}",
                          source, re.S)
        if not match:
            continue
        for key, image in re.findall(r'"([^"]+)"\s*:\s*"([^"]+)"', match.group(1)):
            found[key] = image
    return found


def _node_workloads():
    """The node's Workloads table, read out of internal/compute/catalogue.go.

    Parsed rather than duplicated, for the same reason the language table is:
    a test carrying its own copy of the field would keep passing after the two
    catalogues drifted, which is the entire failure this file exists to catch.

    Returns {name: {GoFieldName: string value}} — only the string fields, which
    is all the file contract needs.
    """
    if not os.path.exists(NODE_CATALOGUE):
        return {}
    with open(NODE_CATALOGUE, encoding="utf-8") as handle:
        source = handle.read()
    table = re.search(r"var Workloads = map\[string\]Workload\{(.*?)\n\}",
                      source, re.S)
    if not table:
        return {}
    found = {}
    for name, block in re.findall(r'"([^"]+)":\s*\{(.*?)\n\t\},',
                                  table.group(1), re.S):
        found[name] = dict(re.findall(r'(\w+):\s*"([^"]*)"', block))
    return found


class WorkloadFilesMatchTheNodeTest(unittest.TestCase):
    """The two catalogues must agree about the FILES, not just the names.

    THE DEFECT THIS WOULD HAVE CAUGHT
    ---------------------------------
    The node's Workload struct had an InputFile and no output field at all. The
    site's copy carried `output_file` and always had. Nothing compared them, so
    the disagreement was invisible: the node dispatched embed jobs with no
    output path, the worker fetches only paths it is given, and the produced
    file was destroyed with the container. The site got a stdout digest, exit 0
    and no vectors — verified by hash equality against a replica's identical
    digest, marked done, and paid for.

    A name in both tables is not agreement. The contract is the file.
    """

    def setUp(self):
        self.node = _node_workloads()
        if not self.node:
            self.fail("the node's Workloads table was not found in %s — if it "
                      "moved, this test has to follow it there rather than be "
                      "deleted, because nothing else compares the two "
                      "catalogues" % NODE_CATALOGUE)

    def test_the_two_catalogues_list_the_same_workloads(self):
        self.assertEqual(set(catalogue.WORKLOADS), set(self.node),
                         "the site's workload table and the node's have "
                         "drifted; one of them is lying to a submitter")

    def test_the_input_file_is_the_same_name_on_both_sides(self):
        for name, spec in catalogue.WORKLOADS.items():
            self.assertEqual(
                spec["input_file"], self.node.get(name, {}).get("InputFile"),
                "%s: the site would deliver the data under a name the node's "
                "image does not read" % name)

    def test_the_output_file_is_the_same_name_on_both_sides(self):
        for name, spec in catalogue.WORKLOADS.items():
            declared = self.node.get(name, {}).get("OutputFile")
            self.assertTrue(
                declared,
                "%s: the node declares no OutputFile, so it asks the container "
                "for nothing and the produced file is deleted with it. The job "
                "then returns exit 0, a digest of a file nobody has, and no "
                "result — which verifies, completes and charges." % name)
            self.assertEqual(
                spec["output_file"], declared,
                "%s: the site looks for %r and the node fetches %r, so the "
                "product arrives under a name nothing reads"
                % (name, spec["output_file"], declared))

    def test_the_input_and_output_are_different_files(self):
        for name, spec in catalogue.WORKLOADS.items():
            self.assertNotEqual(spec["input_file"], spec["output_file"],
                                "%s would overwrite its own input" % name)

    def test_the_image_reference_is_the_same_on_both_sides(self):
        for name, spec in catalogue.WORKLOADS.items():
            self.assertEqual(
                spec["image"], self.node.get(name, {}).get("Image"),
                "%s: the site says the workload runs %r and the node runs %r"
                % (name, spec["image"], self.node.get(name, {}).get("Image")))

    def test_the_published_artifact_is_the_same_name_on_both_sides(self):
        for name, spec in catalogue.WORKLOADS.items():
            self.assertEqual(
                spec["image_artifact"], self.node.get(name, {}).get("Artifact"),
                "%s: the site publishes the image as %r and the node fetches "
                "%r, so every node asking for it gets a 404 and stops "
                "advertising compute"
                % (name, spec["image_artifact"],
                   self.node.get(name, {}).get("Artifact")))

    def test_the_image_digest_is_the_same_on_both_sides(self):
        """The agreement that stops a node loading a DIFFERENT image.

        THE DEFECT THIS CATCHES
        -----------------------
        A node verifies a downloaded image against a sha256 compiled into its
        own binary and refuses to `docker load` anything else — which is the
        only reason fetching an executable image over the network is defensible
        at all. The site's copy is what
        backend/scripts/publish_compute_images.py checks a tarball against
        before storing it.

        If the two drift, the publish step happily stores bytes that every node
        in the fleet then refuses, and the symptom is not an error anywhere near
        the publish: it is compute capacity silently going to zero, visible only
        in volunteers' journals. So the name matching is not enough here — the
        BYTES have to be the same fact on both sides.
        """
        for name, spec in catalogue.WORKLOADS.items():
            declared = self.node.get(name, {}).get("Digest")
            self.assertTrue(
                declared,
                "%s: the node declares no image Digest, so it has nothing to "
                "check a downloaded image against and will refuse to fetch it "
                "at all" % name)
            self.assertEqual(
                spec["image_digest"], declared,
                "%s: the site would publish an artifact hashed %r and the node "
                "will only load %r — publishing succeeds and every node refuses"
                % (name, spec["image_digest"], declared))

    def test_every_digest_is_a_bare_lowercase_sha256(self):
        # A "sha256:"-prefixed or upper-cased value compares unequal to what the
        # node computes, so it would fail every download while looking correct
        # in both files.
        for name, spec in catalogue.WORKLOADS.items():
            self.assertRegex(
                spec["image_digest"], r"^[0-9a-f]{64}$",
                "%s: image_digest must be 64 lowercase hex characters and "
                "nothing else — the node compares it against a bare "
                "hex.EncodeToString" % name)

    def test_the_artifact_names_the_workload_it_carries(self):
        # Not a rule the node enforces, and worth holding anyway: these files
        # sit beside the node binaries under one flat /dl/ namespace, and a
        # tarball called something generic is one somebody replaces by accident.
        for name, spec in catalogue.WORKLOADS.items():
            self.assertEqual(spec["image_artifact"], "compute-%s.tar" % name)
            self.assertEqual(spec["image"], "registry.local/compute-%s:latest" % name)

    def test_an_artifact_name_maps_back_to_exactly_one_workload(self):
        # /dl/ resolves a filename through this table, so two workloads sharing
        # an artifact name would make the route serve whichever it found first.
        for name, spec in catalogue.WORKLOADS.items():
            self.assertEqual(catalogue.artifact_workload(spec["image_artifact"]), name)
        self.assertIsNone(catalogue.artifact_workload("compute-nothing.tar"))
        self.assertIsNone(catalogue.artifact_workload(""))
        seen = [spec["image_artifact"] for spec in catalogue.WORKLOADS.values()]
        self.assertEqual(len(seen), len(set(seen)))


class LanguagesMatchTheNodeTest(unittest.TestCase):
    def setUp(self):
        self.node = _node_catalogue_images()
        if not self.node:
            self.fail("catalogueImages was not found in %s — if the node's "
                      "table moved, this test has to follow it there rather "
                      "than be deleted" % NODE)

    def test_the_site_offers_exactly_what_the_node_can_run(self):
        self.assertEqual(set(catalogue.LANGUAGES), set(self.node),
                         "the site's language list and the node's image table "
                         "have drifted; one of them is lying to a submitter")

    def test_remote_languages_is_the_same_list(self):
        self.assertEqual(set(catalogue.remote_languages()), set(catalogue.LANGUAGES))

    def test_every_language_has_an_image_directory(self):
        for language in catalogue.LANGUAGES:
            self.assertTrue(
                os.path.isdir(os.path.join(IMAGES, language)),
                "%s is offered but compute-images/%s does not exist" % (language, language))

    def test_this_is_not_the_local_judge_list(self):
        # services/code_runner.LANGUAGES governs the operator's own javascript/
        # python judge pod. Merging the two would offer javascript to the
        # network (no image, fails at dispatch) and hide c and go from the
        # arcade judge. Different runners, different lists.
        self.assertNotIn("javascript", catalogue.LANGUAGES)


class WorkloadsHaveImagesTest(unittest.TestCase):
    def test_every_workload_names_an_image_directory(self):
        for name in catalogue.WORKLOADS:
            self.assertTrue(
                os.path.isdir(os.path.join(IMAGES, name)),
                "the %s workload is offered but compute-images/%s does not "
                "exist, so every job submitted for it would fail at dispatch"
                % (name, name))

    def test_a_workload_is_not_also_a_language(self):
        # They are different fields carrying different rules. A name in both
        # would make "does this need an entry point" depend on which one the
        # reader happened to check.
        self.assertFalse(set(catalogue.WORKLOADS) & set(catalogue.LANGUAGES))

    def test_every_workload_states_the_whole_contract(self):
        for name, spec in catalogue.WORKLOADS.items():
            for field in ("label", "input_file", "output_file", "needs_entrypoint",
                          "deterministic", "device", "default_verify_rate", "blurb",
                          # A workload with no artifact or no digest cannot be
                          # obtained by anybody who did not build it by hand,
                          # which is the state D.2 exists to end.
                          "image", "image_artifact", "image_digest"):
                self.assertIn(field, spec, "%s is missing %s" % (name, field))
            self.assertFalse(spec["needs_entrypoint"],
                             "a workload runs a fixed image; there is nothing "
                             "for a submitter to name")

    def test_the_file_names_match_what_the_image_actually_reads(self):
        # The paths are a contract with the image, not a label. embed.py opens
        # /work/input.jsonl and /work/output.jsonl by those literal names, so a
        # site that validated against anything else would accept a job that
        # could only fail on the node.
        path = os.path.join(IMAGES, "embed", "embed.py")
        with open(path, encoding="utf-8") as handle:
            source = handle.read()
        spec = catalogue.workload("embed")
        self.assertIn('INPUT = "/work/%s"' % spec["input_file"], source)
        self.assertIn('OUTPUT = "/work/%s"' % spec["output_file"], source)

    def test_embeddings_are_verified_every_time(self):
        # Bit-exact and cheap, which is why this slice was chosen first. The
        # rental default of 0.25 is a compromise for expensive work; there is
        # no reason to accept it here.
        self.assertEqual(catalogue.default_verify_rate("embed"), 1.0)
        self.assertTrue(catalogue.WORKLOADS["embed"]["deterministic"])

    def test_an_unknown_name_over_verifies_rather_than_trusting(self):
        self.assertFalse(catalogue.is_workload("nope"))
        self.assertIsNone(catalogue.workload("nope"))
        self.assertEqual(catalogue.default_verify_rate("nope"), 0.25)

    def test_helpers_agree_with_the_table(self):
        self.assertEqual(catalogue.workload_names(), tuple(sorted(catalogue.WORKLOADS)))
        self.assertEqual(catalogue.input_file("embed"), "input.jsonl")
        self.assertEqual(catalogue.output_file("embed"), "output.jsonl")
        self.assertIsNone(catalogue.input_file(None))


if __name__ == "__main__":
    unittest.main()
