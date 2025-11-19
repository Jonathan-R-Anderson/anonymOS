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

## Namespace integration

The capability-based namespace described in `docs/NAMESPACE.md` makes VMOs the
sole currency for sharing bytes between processes.  Files, pipes, sockets, and
other IO endpoints expose their payloads by yielding VMO handles or streams of
VMOs.  Because processes only map VMOs rather than naming individual pages, the
kernel can focus on tracking capabilities and permissions while letting the
canonical VMO hashes provide global identity for deduplication and integrity.

## Paging & physical memory

`minimal_os.kernel.paging` extends the reference implementation with a
content-addressed page cache. Page frames are indexed by `(hash, offset)` which
allows the cache to deduplicate both the physical storage and the resident page
objects. A simple RLE compressor is applied opportunistically so that repeated
byte runs occupy less memory, making compression and deduplication natural side
effects of the content-addressed design.

The cache tracks reachability through the VMO DAG. `pin()` walks every child of
the specified root, increments a graph-aware reference count, and keeps page
frames alive while the root is reachable. `unpin()` performs the inverse walk
and immediately evicts the page frames for nodes whose reachability drops to
zero. This ensures reclamation honours DAG structure instead of blindly paging
out data that might still be referenced elsewhere.

Mapping APIs accept NUMA placement hints so callers can express locality needs
when they fault pages. Read-only pages can be replicated to multiple NUMA nodes
without breaking deduplication: replicas reuse the canonical content hash while
maintaining per-node copies. This keeps the mapping layer NUMA-aware without
requiring additional kernel data structures beyond the page cache itself.

## Garbage collection & lifecycle

`VmoStore` exposes lifecycle hooks so the kernel can reason about which VMOs are
still reachable. Kernel subsystems register their live capabilities (process
tables, filesystem inodes, IPC channels, etc.) via `trackCapability(label,
handle)` and periodically call `collectGarbage()`. The collector walks the DAG
from every registered root and from any outstanding `VmoPinLease`, then removes
nodes that are no longer reachable. This lazy reclamation keeps the fast-path
unchanged while ensuring unused subgraphs eventually disappear.

Processes can call `pin(handle)` to obtain a `VmoPinLease` that temporarily
protects the underlying DAG from reclamation. Releasing the lease (explicitly or
via scope exit) decrements the pin count so the collector can reclaim the nodes
again. Pins let higher-level policies enforce quotas without giving processes a
mutable view of the page cache.

Content-addressed pages inside `VmoStore` are backed by a bounded cache. The
constructor accepts a `contentCacheCapacity` that limits the number of unique
page hashes retained at any time. The cache evicts entries using an LRU policy
based on the content hashes so newly faulted data pushes out the least recently
used pages while hot data stays resident.

## Observability & tooling

The immutable, content-addressed nature of VMOs lends itself well to rich
observability hooks that can be used from both the kernel and user space.

* `hash(vmo)` – emits the canonical identifier for any VMO. Because the hash is
  derived from the canonical encoding, it acts as a stable handle in logs,
  trace spans, and deduplication tables regardless of which process materialised
  the object.
* `explain(vmo)` – renders the extent DAG using the same slice/concat/delta
  vocabulary described earlier in this document. This is invaluable when
  debugging complex builders because it surfaces how the final content was
  composed from smaller pieces.
* `profile(map)` – instruments mappings to capture page-fault counts, the cost
  of flattening the DAG into resident pages, and current residency. Operators
  can run it against hot mappings to quickly see whether cost is dominated by
  cold faults, deltas, or repeated flattening.

These primitives make the VMO subsystem transparent: operators can correlate
hashes across logs, inspect problematic graphs, and quantify residency pressure
without reaching into kernel internals.
