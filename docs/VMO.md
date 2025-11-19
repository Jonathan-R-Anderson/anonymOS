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
