# Catalogue images

The signed runtimes a volunteer node will run. A submitter picks one and supplies
**data or source files**; they never supply the image. That is the catalogue
rule, and it exists because a container is not a boundary to run somebody else's
arbitrary code behind.

## Determinism is the requirement, not a nice-to-have

M5 verifies CPU work by running a unit on several unrelated machines and
comparing **hashes**. That only works if two honest nodes produce byte-identical
output, so these images are built to remove the ordinary sources of drift:

| Source of drift | What is done |
|---|---|
| Package versions | pinned; no `latest`, no unpinned `pip install` |
| Locale and timezone | `LC_ALL=C`, `TZ=UTC` — collation and date formatting both change output |
| Hash randomisation | `PYTHONHASHSEED=0` — otherwise dict iteration order varies per run |
| Bytecode caches | `PYTHONDONTWRITEBYTECODE=1` so none is written, plus a `.dockerignore` so the developer's host `__pycache__` never enters the build context — it is bytecode from a different Python, baked into a layer, untracked |
| Build timestamps | `SOURCE_DATE_EPOCH=0` for compiled languages |
| Parallel scheduling | single-threaded by default; a parallel reduction reorders float addition |

**A job that reads the clock, calls an unseeded RNG, or depends on thread
scheduling is not verifiable** whatever the image does. The image removes what it
can; the rest is a property of the submitted program, and M5 marks such work
non-deterministic rather than pretending.

## Not root, not writable

Every image runs as an unprivileged user with a read-only root. The writable
paths are `/tmp` and the job's own `/work` mount, both memory-backed and both
discarded with the container. Nothing survives to the next job — persistence
across jobs is how one compromise becomes a permanent one.

`/work` must arrive writable **by uid 10001**, not by root and not by the host
user. A root-owned mount fails with `EACCES` at the moment the job writes its
result, i.e. after all the work is done, so `embed/run.sh` checks up front and
exits 2 naming the cause instead of letting a Python traceback stand in for it.

## Two kinds of image

`python`, `c` and `go` are **language runtimes**: the submitter supplies a
program and names an entrypoint inside `/work`, and the image runs it. Arbitrary
code, gated on M2 isolation.

`embed` is a **fixed workload**: the code is baked in at build time and the
submitter supplies only data. Nothing the submitter sends decides what executes,
which is why this one is deployable without arbitrary-code execution being
defensible first. `ENTRYPOINT` is accepted and ignored — the image *is* the
workload.

## The `embed` workload contract (M10 slice 1)

| | |
|---|---|
| Image | `registry.local/compute-embed:latest` |
| Data in | `/work/input.jsonl` — one JSON object per line, `{"id": ..., "text": ...}` |
| Vectors out | `/work/output.jsonl` — one line per input line, **in input order** |
| Result on stdout | exactly one line: `embed-digest sha256:<hex> count:<n>` |
| Model | `sentence-transformers/all-MiniLM-L6-v2`, pinned by revision, baked in |
| Vector | 384-dim, mean-pooled, L2-normalised, little-endian float32 as hex |

Each output line is `{"dim":384,"id":"...","vec":"<hex>"}` with sorted keys and
no spaces. The hex is the raw float32 bytes: this output exists to be *compared*,
not read, and decimal formatting of floats is not reproducible across libc
versions.

**Stdout is the verification surface.** `backend/services/compute_verify.py`
hashes stdout plus the exit code (`output_digest`) and compares that between
replicas — so the digest line proves the vectors match without shipping them
twice, and *anything else printed to stdout is a disagreement between two honest
nodes*. Diagnostics go to stderr, which `output_digest` excludes on purpose.

### Exit codes

| Code | Meaning | Whose problem |
|---|---|---|
| 0 | success; digest on stdout | — |
| 2 | no `/work/input.jsonl`, or `/work` not writable | **plumbing** — the runner never set the job up |
| 3 | a line is not a JSON object (line number on stderr) | submitter's data |
| 4 | a line is missing `id` or `text` (line number on stderr) | submitter's data |
| 5 | the container cannot produce comparable output (e.g. a non-CPU execution provider) | the image/node |

2 is reserved for plumbing because the language images already exit 2 for
"entrypoint not found": the site reads 2 as *the work never started*. Folding
malformed data into the same code — which is what this image used to do — means
a caller cannot tell a broken mount from a bad shard, so it retries a hopeless
job forever or charges a node for the runner's mistake.

### The submitter never names the image

The node picks `registry.local/compute-embed:latest` from its own workload table
in `storage-client/internal/compute/catalogue.go`, keyed by workload name,
exactly as `catalogueImages` in `cmd/syndichan-node/computeapi.go` is keyed by
language. Both tables are closed: a name in neither is refused rather than
forwarded as an image reference. A request carries a workload *name* and data,
never an image.

## Building

    ./compute-images/build.sh          # all: python c go embed
    ./compute-images/build.sh python   # one

Images are tagged `registry.local/compute-<name>:latest`, built with Docker and
then imported into containerd, because `registry.local` is not a real registry
and a built image the node cannot pull fails at dispatch.

## Publishing, so a volunteer who is not you can run the workload

Building locally is fine for a fleet you administer and is not a distribution
story. A catalogue **workload** image is published the same way the node binary
is — content-addressed into the object store, indexed by one SiteSetting, served
at `/dl/<artifact>` with a `.sha256` sidecar:

    ./scripts/publish-compute-images.sh --save-only   # save + hash, publish nothing
    ./scripts/publish-compute-images.sh               # save + publish
    ./scripts/publish-compute-images.sh --build       # docker build first

A node that offers compute then fetches whatever it lacks, **verifies the
SHA-256 against a value compiled into its own binary**, and `docker load`s it.
So the order matters and the script will not let you skip it:

1. build the image;
2. `docker save` it and take its sha256 (`--save-only` stops here);
3. if that hash is not already in the two catalogue tables, put it in **both** —
   `backend/services/compute_catalogue.py` (`image_digest`) and
   `storage-client/internal/compute/catalogue.go` (`Digest`) — and ship a node
   build carrying it. Until nodes run that build they refuse the new artefact,
   which is the intended behaviour: it is what stops a compromised origin
   replacing the image every volunteer runs;
4. publish. This step **refuses** a tarball whose hash is not the declared one,
   so a forgotten step 3 fails at a terminal instead of as a fleet-wide loss of
   compute capacity.

`docker save` is byte-stable for a given image on a given daemon (measured: two
consecutive saves of `compute-embed` produced the same sha256, 194,401,280
bytes), so re-saving re-derives the hash. Rebuilding from the Dockerfile does
**not** reproduce it, and nothing claims otherwise — the digest describes the
published tarball, not the Dockerfile.

Not gzipped: `docker save` already stores its layers compressed, and gzip -6
took 194,401,280 bytes to 193,749,973 — 0.33%, for a compression step on every
publish and a decompression step on every node.

**The language images are deliberately not published.** `python`, `c` and `go`
run submitted programs and are gated on microVM isolation; distributing an
arbitrary-code runtime to nodes that must refuse arbitrary code would buy
nothing. They remain build-locally-only, and a node's compute advertisement does
not depend on them.

### What a node does with a missing image

It stops advertising compute. Not "advertises and refuses" — the operator's
model is that a node offering compute does not choose which catalogue workloads
it takes, so being unable to run the catalogue is being unable to offer compute.
See `storage-client/internal/computeimage`.

### `embed` has never been built

Stated plainly because everything above is a design, not a measurement. The
first build needs:

* **network** — the model is fetched once, at build time, from Hugging Face;
* **root** — `build.sh` shells out to `docker` and `k3s ctr` (run it from a real
  terminal, it cannot answer a sudo prompt);
* **~500 MB** of image, most of it onnxruntime and the ONNX weights;
* time — the `pip install` and the model download dominate.

Three things the first build (and first two-node run) has to actually confirm,
none of which can be asserted from here:

1. the pinned revision still carries `onnx/model.onnx` — the Dockerfile now
   `test -f`s it, because `snapshot_download` returns happily when
   `allow_patterns` match nothing;
2. `/work` arrives writable by uid 10001, or every job dies at the last line
   after doing all the work (`run.sh` checks this up front and says so);
3. **that two different CPUs agree.** The image removes threading, locale,
   optimisation-level and version drift, but onnxruntime's CPU kernels dispatch
   on the host's instruction set, and an AVX-512 GEMM need not sum to the same
   float32 bits as an AVX2 one. If that turns out to differ, slice 1's premise
   fails on real hardware and the fix is a kernel-level constraint, not a
   tolerance window — so run the same shard on two unlike machines before
   trusting a single digest comparison.
