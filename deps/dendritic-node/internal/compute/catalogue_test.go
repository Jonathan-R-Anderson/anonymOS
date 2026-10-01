package compute

import (
	"errors"
	"strings"
	"testing"
)

// --- M10: the closed table ---

func TestAnUnknownWorkloadIsRefusedNotResolved(t *testing.T) {
	// The property the whole table exists for. A name that is not in the
	// catalogue must not produce something runnable — not an empty image, not a
	// default, not the name itself passed through as a reference.
	for _, name := range []string{"", "nope", "ubuntu", "registry.local/compute-embed:latest", "EMBED"} {
		w, ok := LookupWorkload(name)
		if ok {
			t.Errorf("resolved %q as a workload", name)
		}
		if w.Image != "" {
			t.Errorf("a failed lookup of %q still yielded image %q", name, w.Image)
		}
	}
}

func TestTheOnlyWorkloadIsDataOnly(t *testing.T) {
	// M10 slice 1 is deployable today precisely because it runs fixed code over
	// submitted data. A catalogue entry that wanted an entrypoint would be a
	// language image wearing a workload's name, and it would need M2 first.
	for name, w := range Workloads {
		if w.NeedsEntrypoint {
			t.Errorf("workload %q takes an entrypoint, which is arbitrary code by another name", name)
		}
		if w.Name != name {
			t.Errorf("workload keyed %q calls itself %q", name, w.Name)
		}
		if w.Class == "" {
			t.Errorf("workload %q declares no class, so no operator can filter on it", name)
		}
		if w.DefaultDeadline <= 0 {
			t.Errorf("workload %q has no default deadline, so a caller who omits one gets an unbounded job", name)
		}
		if w.InputFile == "" {
			t.Errorf("workload %q declares no input file, so nothing can deliver its data", name)
		}
		// The defect this field was added for: a workload's answer is a FILE,
		// and the node only fetches paths it was told to fetch. Undeclared, the
		// result is deleted with the container and the job reports a clean exit
		// with nothing in it — which the site verifies by hash and pays for.
		if w.OutputFile == "" {
			t.Errorf("workload %q declares no output file, so whatever it produces "+
				"is destroyed with the container and the job looks like a success", name)
		}
		if w.InputFile == w.OutputFile {
			t.Errorf("workload %q reads and writes %q; the image would overwrite its own input",
				name, w.InputFile)
		}
	}
}

func TestEmbedIsVerifiableByHashEquality(t *testing.T) {
	// Deterministic is what selects M5's instrument. If this flipped, honest
	// replicas would be compared with the wrong test and scored as faults.
	embed, ok := LookupWorkload("embed")
	if !ok {
		t.Fatal("the catalogue lost its only workload")
	}
	if !embed.Deterministic {
		t.Fatal("embed must be deterministic; it is verified bit-exact")
	}
	if embed.InputFile == "" {
		t.Fatal("embed declares no input file, so nothing can deliver its data")
	}
	// The literal names compute-images/embed/embed.py opens. They are a
	// contract with the image rather than a label: it reads /work/input.jsonl
	// and writes /work/output.jsonl by those names and takes no path argument,
	// so a table that said anything else would describe a job that could only
	// fail. backend/tests/test_compute_catalogue.py checks the same two strings
	// against the site's copy and against embed.py itself.
	if embed.InputFile != "input.jsonl" || embed.OutputFile != "output.jsonl" {
		t.Fatalf("embed reads %q and writes %q; the image uses input.jsonl and output.jsonl",
			embed.InputFile, embed.OutputFile)
	}
}

// --- UnitFor ---

func TestUnitForBuildsAValidatingUnit(t *testing.T) {
	embed, _ := LookupWorkload("embed")
	unit, err := UnitFor(embed, "cpu", map[string]string{"model": "minilm"}, 7, 120)
	if err != nil {
		t.Fatalf("could not build a unit for the catalogue's own workload: %v", err)
	}
	if unit.Runtime != embed.Image {
		t.Fatalf("runtime = %q, want the catalogue image %q", unit.Runtime, embed.Image)
	}
	if unit.Class != embed.Class || unit.Deterministic != embed.Deterministic {
		t.Fatal("the unit disagreed with the catalogue about what this workload is")
	}
	if unit.Needs != "cpu" || unit.Seed != 7 || unit.DeadlineSeconds != 120 {
		t.Fatalf("unit did not carry its arguments: %+v", unit)
	}
	if err := unit.Validate(); err != nil {
		t.Fatalf("UnitFor returned a unit that does not validate: %v", err)
	}
	if unit.Digest() == "" {
		t.Fatal("a unit with no digest has no identity")
	}
}

func TestUnitForRefusesAWorkloadThatDidNotComeFromTheTable(t *testing.T) {
	// The second lock on the closed table. Even a caller who hand-builds a
	// Workload cannot name an image with it, because Validate only accepts
	// runtimes the catalogue actually lists.
	forged := Workload{Name: "evil", Image: "ubuntu:latest", Class: "index", DefaultDeadline: 600}
	if _, err := UnitFor(forged, "cpu", nil, 0, 0); err == nil {
		t.Fatal("built a unit naming an image that is not in the catalogue")
	}
}

func TestUnitForRefusesAZeroWorkload(t *testing.T) {
	// What a caller who skipped LookupWorkload and indexed the map directly
	// would hand over. Refused rather than run as the empty image.
	_, err := UnitFor(Workload{}, "cpu", nil, 0, 0)
	if !errors.Is(err, ErrUnknownWorkload) {
		t.Fatalf("err = %v, want ErrUnknownWorkload", err)
	}
}

func TestUnitForFallsBackToTheWorkloadsDeadline(t *testing.T) {
	embed, _ := LookupWorkload("embed")
	unit, err := UnitFor(embed, "cpu", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if unit.DeadlineSeconds != embed.DefaultDeadline {
		t.Fatalf("deadline = %d, want the workload default %d", unit.DeadlineSeconds, embed.DefaultDeadline)
	}
}

func TestUnitForDefaultsToCPUButRefusesNonsense(t *testing.T) {
	embed, _ := LookupWorkload("embed")
	unit, err := UnitFor(embed, "", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if unit.Needs != "cpu" {
		t.Fatalf("needs = %q, want the conservative default", unit.Needs)
	}
	if _, err := UnitFor(embed, "quantum", nil, 0, 0); err == nil {
		t.Fatal("accepted a device no node can advertise, which would queue forever")
	}
}

func TestParamsAreCopiedSoIdentityCannotChangeAfterTheFact(t *testing.T) {
	// The digest is the unit's identity. A caller still holding the map could
	// otherwise change what the unit says AFTER it was hashed, and the ticket
	// the site holds would no longer describe the work.
	embed, _ := LookupWorkload("embed")
	params := map[string]string{"model": "minilm"}
	unit, err := UnitFor(embed, "cpu", params, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	before := unit.Digest()
	params["model"] = "something-else"
	if unit.Digest() != before {
		t.Fatal("mutating the caller's map changed the unit's identity")
	}
}

func TestTwoIdenticalSubmissionsAreOneUnit(t *testing.T) {
	// Idempotence, at the level the bridge sees it: the ticket for the same
	// work is the same string, so a redistributed unit is one fact and not two.
	embed, _ := LookupWorkload("embed")
	a, _ := UnitFor(embed, "cpu", map[string]string{"k": "v"}, 3, 60)
	b, _ := UnitFor(embed, "cpu", map[string]string{"k": "v"}, 3, 60)
	if a.Digest() != b.Digest() {
		t.Fatal("the same submission produced two identities")
	}
	c, _ := UnitFor(embed, "cpu", map[string]string{"k": "v"}, 4, 60)
	if c.Digest() == a.Digest() {
		t.Fatal("a different seed produced the same identity, so a reseeded run could not be distinguished")
	}
}

func TestOnlyCatalogueImagesCountAsCatalogueRuntimes(t *testing.T) {
	embed, _ := LookupWorkload("embed")
	if !IsCatalogueRuntime(embed.Image) {
		t.Fatal("the catalogue does not recognise its own image")
	}
	for _, other := range []string{
		"", "ubuntu:latest", "registry.local/compute-python:latest",
		"registry.local/compute-embed", strings.ToUpper(embed.Image),
	} {
		if IsCatalogueRuntime(other) {
			t.Errorf("accepted %q as a catalogue image", other)
		}
	}
}
