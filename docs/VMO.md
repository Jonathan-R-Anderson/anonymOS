# Virtual Memory Objects (VMOs)

The minimal OS models files and anonymous mappings as immutable Virtual Memory
Objects that are addressed by the hash of their canonical content.  The hash is
derived from a canonical byte stream that encodes both the extent graph and the
bytes contained in the leaves.  VMOs are stored in a Directed Acyclic Graph of
**extents**, very similar to a rope:

* **Page extents** – leaves that contain up to a page worth of bytes.  These are
  the only extents that actually store bytes.
* **Slice extents** – reference a sub-range of another VMO without copying.
* **Concat extents** – concatenate two or more extents, allowing large VMOs to
  be composed from existing pieces.
* **Delta extents** – wrap another VMO and describe sparse patches that should
  be overlaid onto the base when materialised.

Because the canonical stream encodes the structure, two logically identical VMOs
share the same hash (and therefore the same identity) regardless of how they
were constructed.  VMOs are immutable, so deduplication can happen at every
level of the graph: identical page extents, identical slice descriptions, and so
on.

## Lazy page materialisation

VMOs are mapped into address spaces on demand.  The kernel walks the extent DAG
to find the leaf that backs the faulting virtual page and only materialises the
exact bytes required.  Materialised pages are cached and deduplicated by their
content hash, ensuring that repeated faults for the same data never allocate new
physical frames.  This deduplication also enables copy-on-write semantics
between different VMOs that happen to share content.

## Reference implementation

The `src/minimal_os/kernel/vmo.d` module contains a D implementation that runs
inside the guest OS.  It exposes a `VmoStore` for constructing immutable VMOs
alongside `VmoHandle` helpers that lazily materialise pages and deduplicate them
via their content hashes.  The accompanying unit tests (run via
``ldc2 -unittest tests/vmo_test_runner.d``) exercise slicing, concatenation,
delta overlays, and page cache sharing to ensure the canonical encoding and lazy
faulting behaviour match the specification.

## VBuilder – staged writers

VMOs are immutable, so writes must be staged through a `VBuilder`. Builders are
ephemeral objects that keep a private log of appends and patches. The log is not
visible to other components which makes builders the only authority that can
produce a new immutable VMO once `commit()` is invoked. Committing seals the log
and returns a `VmoHandle` capability referencing the new content. Any further
attempt to append or patch after committing raises an error, reinforcing that
VMOs themselves never change.

`VmoStore` can provision builders in two flavours:

* `boundedBuilder(maxBytes)` – enforces an upper bound on the total number of
  bytes appended, making it ideal for pre-sized blobs.
* `streamingBuilder()` – intended for pipes or ingestion where the caller keeps
  pushing chunks without a known upper bound.

Both builder types expose the same API:

* `append(bytes)` – records a chunk into the private log (zero-length chunks are
  ignored).
* `patch(offset, bytes)` – records a sparse overlay that is applied when the log
  is sealed.
* `commit()` – concatenates all append chunks, overlays the recorded patches,
  and returns the resulting immutable `VmoHandle`.

Internally builders reuse the existing extent machinery, so incremental writes
benefit from deduplication and can share physical pages once committed.
