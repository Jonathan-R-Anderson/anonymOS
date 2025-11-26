module anonymos.kernel.vmo;

import core.atomic : atomicCompareExchange, atomicExchange, atomicLoad, atomicStore;
import std.algorithm : max, min, sort;
import std.array : appender, Appender;
import std.digest.sha : sha256Of;
import std.exception : enforce;
import anonymos.kernel.numa : NumaNode, NumaPlacementHint;

alias ByteSlice = immutable(ubyte)[];

class VmoStore;
struct VmoHandle;
struct DeltaPatch;
struct CachedPage;
struct CapabilityRecord;
struct CapabilityAnchor;
struct VmoPinLease;

enum VBuilderMode : ubyte
{
    bounded,
    streaming,
}

struct VmoCommitMetadata
{
    string[string] tags;
}

struct VmoCommitResult
{
    VmoHandle handle;
    HashBytes hash;
    size_t length;
    VmoCommitMetadata metadata;
}

final class VBuilder
{
public:
    this(VmoStore store, VBuilderMode mode, size_t limit)
    {
        enforce(store !is null, "store cannot be null");
        _store = store;
        _mode = mode;
        _limit = limit;
    }

    @property size_t length() const
    {
        return _length;
    }

    void append(const scope ubyte[] data)
    {
        ensureActive();
        if (data.length == 0)
        {
            return;
        }
        enforce(!isBounded || data.length <= available(), "builder capacity exceeded");
        auto handle = _store.fromBytes(data);
        _segments ~= handle;
        _length += data.length;
    }

    void write(size_t offset, const scope ubyte[] data)
    {
        ensureActive();
        enforce(offset <= _length, "write offset beyond current builder length");
        if (data.length == 0)
        {
            return;
        }
        if (offset == _length)
        {
            append(data);
            return;
        }
        enforce(offset + data.length <= _length, "write exceeds staged length");
        patch(offset, data);
    }

    void copyFrom(VmoHandle source, size_t sourceOffset, size_t length, size_t destinationOffset)
    {
        ensureActive();
        enforce(sourceOffset + length <= source.length, "copy exceeds source length");
        auto data = source.read(sourceOffset, length);
        write(destinationOffset, data);
    }

    void patch(size_t offset, const scope ubyte[] data)
    {
        ensureActive();
        enforce(data.length > 0, "patch requires data");
        enforce(offset + data.length <= _length, "patch exceeds written length");
        _patches ~= makePatch(offset, data);
    }

    VmoCommitResult commit(VmoCommitMetadata metadata = VmoCommitMetadata.init)
    {
        ensureActive();
        scope(exit)
        {
            _committed = true;
            _segments.length = 0;
            _patches.length = 0;
        }

        auto base = buildBase();
        auto handle = _patches.length == 0 ? base : _store.delta(base, _patches);
        return VmoCommitResult(handle, handle.hash, handle.length, metadata);
    }

private:
    VmoStore _store;
    VBuilderMode _mode;
    size_t _limit;
    size_t _length;
    bool _committed;
    VmoHandle[] _segments;
    DeltaPatch[] _patches;

    bool get isBounded() const
    {
        return _mode == VBuilderMode.bounded;
    }

    size_t available() const
    {
        if (!isBounded)
        {
            return size_t.max - _length;
        }
        enforce(_length <= _limit, "builder exceeded declared limit");
        return _limit - _length;
    }

    void ensureActive() const
    {
        enforce(!_committed, "builder already committed");
    }

    VmoHandle buildBase()
    {
        if (_segments.length == 0)
        {
            const(ubyte)[] empty;
            return _store.fromBytes(empty);
        }
        if (_segments.length == 1)
        {
            return _segments[0];
        }
        return _store.concat(_segments);
    }
}

private enum NodeKind : ubyte
{
    page,
    slice,
    concat,
    delta,
}

struct HashBytes
{
    ubyte[32] data;

    static HashBytes fromBytes(const scope ubyte[] bytes)
    {
        return fromDigest(sha256Of(bytes));
    }

    static HashBytes fromDigest(const ubyte[32] digest)
    {
        HashBytes h;
        h.data = digest;
        return h;
    }

    bool opEquals(const HashBytes rhs) const @safe pure nothrow
    {
        return data == rhs.data;
    }

    size_t toHash() const @safe pure nothrow
    {
        size_t hash = size_t(0xcbf29ce484222325);
        foreach (b; data)
        {
            hash ^= b;
            hash *= size_t(0x100000001b3);
        }
        return hash;
    }
}

struct PagePayload
{
    ByteSlice bytes;
}

struct SlicePayload
{
    HashBytes base;
    size_t offset;
}

struct ConcatPayload
{
    HashBytes[] children;
}

struct DeltaPatch
{
    size_t offset;
    ByteSlice data;

    bool opEquals(const DeltaPatch rhs) const @safe pure nothrow
    {
        return offset == rhs.offset && data == rhs.data;
    }
}

struct DeltaPayload
{
    HashBytes base;
    DeltaPatch[] patches;
}

struct Node
{
    NodeKind kind;
    size_t length;
    PagePayload page;
    SlicePayload slice;
    ConcatPayload concat;
    DeltaPayload delta;
}

struct PageEntry
{
    size_t index;
    ByteSlice data;

    bool opEquals(const PageEntry rhs) const @safe pure nothrow
    {
        return index == rhs.index && data == rhs.data;
    }
}

struct PageRange
{
    private VmoStore _store;
    private HashBytes _hash;
    private size_t _index;
    private size_t _total;

    this(VmoStore store, HashBytes hash)
    {
        _store = store;
        _hash = hash;
        auto len = store.nodeLength(hash);
        _total = len == 0 ? 0 : (len + store.pageSize - 1) / store.pageSize;
    }

    @property bool empty() const
    {
        return _index >= _total;
    }

    PageEntry front()
    {
        enforce(!empty, "cannot access front of empty range");
        return PageEntry(_index, _store.materializePage(_hash, _index));
    }

    void popFront()
    {
        enforce(!empty, "cannot pop empty range");
        ++_index;
    }
}

struct VmoHandle
{
    private VmoStore _store;
    private HashBytes _hash;

    this(VmoStore store, HashBytes hash)
    {
        _store = store;
        _hash = hash;
    }

    @property HashBytes hash() const
    {
        return _hash;
    }

    @property VmoStore store() const
    {
        return _store;
    }

    @property size_t length() const
    {
        return _store.nodeLength(_hash);
    }

    alias contentId = hash;

    ByteSlice read(size_t offset = 0, size_t length = size_t.max) const
    {
        enforce(offset <= this.length, "offset beyond end of object");
        auto remaining = this.length - offset;
        size_t desired = length == size_t.max ? remaining : length;
        enforce(desired <= remaining, "requested range extends beyond end of object");
        return _store.readSpan(_hash, offset, desired);
    }

    ByteSlice materialize() const
    {
        return read(0, this.length);
    }

    ByteSlice materializePage(size_t pageIndex) const
    {
        return _store.materializePage(_hash, pageIndex);
    }

    PageRange iterPages() const
    {
        return PageRange(_store, _hash);
    }

    VmoMapping map(size_t address = 0, MappingProt prot = MappingProt.read, NumaPlacementHint hint = NumaPlacementHint.automatic()) const
    {
        enforce(prot == MappingProt.read, "only read-only mappings are supported");
        return VmoMapping(this, address, prot, hint);
    }
}

enum MappingProt : uint
{
    read = 1,
    write = 2,
    execute = 4,
}

struct VmoMapping
{
    VmoHandle handle;
    size_t address;
    MappingProt prot;
    NumaPlacementHint numaHint;
}

struct PageKey
{
    HashBytes node;
    size_t index;

    bool opEquals(const PageKey rhs) const @safe pure nothrow
    {
        return index == rhs.index && node == rhs.node;
    }

    size_t toHash() const @safe pure nothrow
    {
        size_t hash = node.toHash();
        hash ^= index + 0x9e3779b97f4a7c15 + (hash << 6) + (hash >> 2);
        return hash;
    }
}

struct CachedPage
{
    ByteSlice data;
    HashBytes contentHash;
}

class VmoStore
{
public:
    this(size_t pageSize = 4096, size_t contentCacheCapacity = 1024)
    {
        enforce(pageSize > 0, "pageSize must be positive");
        enforce(contentCacheCapacity > 0, "content cache capacity must be positive");
        _pageSize = pageSize;
        _contentCacheCapacity = contentCacheCapacity;
    }

    @property size_t pageSize() const
    {
        return _pageSize;
    }

    CapabilityAnchor trackCapability(string label, VmoHandle handle)
    {
        enforce(label.length > 0, "capability label cannot be empty");
        enforce(handle.store is this, "cannot track handle from another VmoStore");
        auto id = _nextCapabilityId++;
        CapabilityRecord record;
        record.label = label;
        record.hash = handle.hash;
        _capabilityRoots[id] = record;
        return CapabilityAnchor(this, id);
    }

    VmoPinLease pin(VmoHandle handle)
    {
        enforce(handle.store is this, "cannot pin handle from another VmoStore");
        addPin(handle.hash);
        return VmoPinLease(this, handle.hash);
    }

    void collectGarbage()
    {
        bool[HashBytes] visited;
        HashBytes[] stack;
        foreach (_, record; _capabilityRoots)
        {
            stack ~= record.hash;
        }
        foreach (hash, _; _pinCounts)
        {
            stack ~= hash;
        }

        while (stack.length > 0)
        {
            auto current = stack[$ - 1];
            stack.length -= 1;
            if (auto seen = current in visited)
            {
                if (*seen)
                {
                    continue;
                }
            }
            visited[current] = true;
            if ((current in _nodes) is null)
            {
                continue;
            }
            foreach (child; childHashes(current))
            {
                stack ~= child;
            }
        }

        HashBytes[] victims;
        foreach (hash, _; _nodes)
        {
            auto seen = hash in visited;
            if (seen is null || !*seen)
            {
                victims ~= hash;
            }
        }

        foreach (victim; victims)
        {
            discardNode(victim);
        }
    }

    VmoHandle page(const scope ubyte[] data)
    {
        enforce(data.length <= pageSize, "page extent larger than configured page size");
        Node node;
        node.kind = NodeKind.page;
        node.length = data.length;
        node.page.bytes = data.idup;
        return intern(node);
    }

    VmoHandle fromBytes(const scope ubyte[] data)
    {
        if (data.length == 0)
        {
            return page(data);
        }

        VmoHandle[] pages;
        pages.reserve((data.length + pageSize - 1) / pageSize);
        size_t start = 0;
        while (start < data.length)
        {
            auto end = min(start + pageSize, data.length);
            pages ~= page(data[start .. end]);
            start = end;
        }

        if (pages.length == 1)
        {
            return pages[0];
        }
        return concat(pages);
    }

    VmoHandle slice(VmoHandle handle, size_t offset, size_t length)
    {
        enforce(offset + length <= handle.length, "slice exceeds source length");
        Node node;
        node.kind = NodeKind.slice;
        node.length = length;
        node.slice.base = handle.hash;
        node.slice.offset = offset;
        return intern(node);
    }

    VmoHandle concat(const scope VmoHandle[] handles)
    {
        enforce(handles.length > 0, "concat requires at least one handle");
        Node node;
        node.kind = NodeKind.concat;
        size_t total = 0;
        node.concat.children.length = handles.length;
        foreach (idx, handle; handles)
        {
            node.concat.children[idx] = handle.hash;
            total += handle.length;
        }
        node.length = total;
        return intern(node);
    }

    VmoHandle delta(VmoHandle base, const scope DeltaPatch[] overlays)
    {
        DeltaPatch[] normalized;
        normalized.reserve(overlays.length);
        foreach (patch; overlays)
        {
            if (patch.data.length == 0)
            {
                continue;
            }
            normalized ~= DeltaPatch(patch.offset, patch.data.idup);
        }
        if (normalized.length == 0)
        {
            return base;
        }
        sort!((a, b) => a.offset < b.offset)(normalized);

        Node node;
        node.kind = NodeKind.delta;
        node.length = base.length;
        node.delta.base = base.hash;
        node.delta.patches = normalized;
        return intern(node);
    }

    VmoHandle diff(VmoHandle oldVersion, VmoHandle newVersion)
    {
        enforce(oldVersion.length == newVersion.length, "diff requires equal lengths");
        auto oldBytes = oldVersion.materialize();
        auto newBytes = newVersion.materialize();
        DeltaPatch[] patches;
        size_t idx = 0;
        while (idx < oldBytes.length)
        {
            if (oldBytes[idx] == newBytes[idx])
            {
                ++idx;
                continue;
            }
            auto start = idx;
            while (idx < oldBytes.length && oldBytes[idx] != newBytes[idx])
            {
                ++idx;
            }
            patches ~= makePatch(start, newBytes[start .. idx]);
        }
        return delta(oldVersion, patches);
    }

    VBuilder createBuilder(size_t sizeHint)
    {
        if (sizeHint == 0 || sizeHint == size_t.max)
        {
            return streamingBuilder();
        }
        return boundedBuilder(sizeHint);
    }

    VBuilder boundedBuilder(size_t maxBytes)
    {
        return new VBuilder(this, VBuilderMode.bounded, maxBytes);
    }

    VBuilder streamingBuilder()
    {
        return new VBuilder(this, VBuilderMode.streaming, 0);
    }

    size_t nodeLength(HashBytes hash) const
    {
        auto ptr = hash in _nodes;
        enforce(ptr !is null, "unknown node hash");
        return (*ptr).length;
    }

    @property size_t nodeCount() const
    {
        return _nodes.length;
    }

    bool contains(HashBytes hash) const
    {
        return (hash in _nodes) !is null;
    }

    @property size_t uniquePageCount() const
    {
        return _pagePool.length;
    }

    ByteSlice materializePage(HashBytes hash, size_t pageIndex)
    {
        PageKey key = PageKey(hash, pageIndex);
        auto cached = key in _pageCache;
        if (cached !is null)
        {
            touchContentCache((*cached).contentHash);
            return (*cached).data;
        }

        auto len = nodeLength(hash);
        auto start = pageIndex * pageSize;
        enforce(start < len, "page index outside of object");
        auto end = min(start + pageSize, len);
        auto page = readSpan(hash, start, end - start);

        auto digest = HashBytes.fromBytes(page);
        auto pooled = digest in _pagePool;
        if (pooled is null)
        {
            _pagePool[digest] = page;
            pooled = digest in _pagePool;
        }
        touchContentCache(digest);
        enforceContentCapacity();
        CachedPage entry;
        entry.data = *pooled;
        entry.contentHash = digest;
        _pageCache[key] = entry;
        return entry.data;
    }

    ByteSlice readSpan(HashBytes hash, size_t offset, size_t length)
    {
        if (length == 0)
        {
            return ByteSlice.init;
        }
        auto nodePtr = hash in _nodes;
        enforce(nodePtr !is null, "unknown node hash");
        auto node = *nodePtr;

        final switch (node.kind)
        {
        case NodeKind.page:
            return node.page.bytes[offset .. offset + length];
        case NodeKind.slice:
            return readSpan(node.slice.base, node.slice.offset + offset, length);
        case NodeKind.concat:
            return readConcat(node.concat.children, offset, length);
        case NodeKind.delta:
            return readDelta(node.delta, offset, length);
        }
        assert(0, "unreachable");
    }

    HashBytes[] childHashes(HashBytes hash) const
    {
        auto nodePtr = hash in _nodes;
        enforce(nodePtr !is null, "unknown node hash");
        auto node = *nodePtr;
        HashBytes[] children;
        final switch (node.kind)
        {
        case NodeKind.page:
            break;
        case NodeKind.slice:
            children ~= node.slice.base;
            break;
        case NodeKind.concat:
            children = node.concat.children.idup;
            break;
        case NodeKind.delta:
            children ~= node.delta.base;
            break;
        }
        return children;
    }

private:
    size_t _pageSize;
    Node[HashBytes] _nodes;
    CachedPage[PageKey] _pageCache;
    ByteSlice[HashBytes] _pagePool;
    size_t _contentCacheCapacity;
    size_t _contentClock;
    size_t[HashBytes] _contentUsage;
    CapabilityRecord[size_t] _capabilityRoots;
    size_t _nextCapabilityId;
    size_t[HashBytes] _pinCounts;

    void touchContentCache(HashBytes digest)
    {
        auto tick = ++_contentClock;
        _contentUsage[digest] = tick;
    }

    void enforceContentCapacity()
    {
        while (_pagePool.length > _contentCacheCapacity)
        {
            HashBytes victim;
            size_t oldest = size_t.max;
            bool found = false;
            foreach (hash, _; _pagePool)
            {
                auto tickPtr = hash in _contentUsage;
                size_t tick = tickPtr is null ? 0 : *tickPtr;
                if (tick < oldest)
                {
                    oldest = tick;
                    victim = hash;
                    found = true;
                }
            }
            if (!found)
            {
                break;
            }
            _pagePool.remove(victim);
            _contentUsage.remove(victim);
            purgePageCacheForContent(victim);
        }
    }

    void purgePageCacheForContent(HashBytes digest)
    {
        PageKey[] stale;
        foreach (key, entry; _pageCache)
        {
            if (entry.contentHash == digest)
            {
                stale ~= key;
            }
        }
        foreach (victim; stale)
        {
            _pageCache.remove(victim);
        }
    }

    void discardNode(HashBytes hash)
    {
        _nodes.remove(hash);
        PageKey[] stale;
        foreach (key, _; _pageCache)
        {
            if (key.node == hash)
            {
                stale ~= key;
            }
        }
        foreach (victim; stale)
        {
            _pageCache.remove(victim);
        }
    }

    void updateCapabilityRoot(size_t id, HashBytes hash)
    {
        auto rec = id in _capabilityRoots;
        enforce(rec !is null, "unknown capability root");
        (*rec).hash = hash;
    }

    void unregisterCapabilityRoot(size_t id)
    {
        enforce((id in _capabilityRoots) !is null, "unknown capability root");
        _capabilityRoots.remove(id);
    }

    void addPin(HashBytes hash)
    {
        auto ptr = hash in _pinCounts;
        size_t count = ptr is null ? 0 : *ptr;
        _pinCounts[hash] = count + 1;
    }

    void releasePin(HashBytes hash)
    {
        auto ptr = hash in _pinCounts;
        enforce(ptr !is null && *ptr > 0, "pin underflow");
        auto updated = *ptr - 1;
        if (updated == 0)
        {
            _pinCounts.remove(hash);
        }
        else
        {
            _pinCounts[hash] = updated;
        }
    }

    VmoHandle intern(Node node)
    {
        auto canonical = canonicalize(node);
        auto digest = HashBytes.fromBytes(canonical);
        if (auto existing = digest in _nodes)
        {
            return VmoHandle(this, digest);
        }
        _nodes[digest] = node;
        return VmoHandle(this, digest);
    }

    static ByteSlice canonicalize(const scope Node node)
    {
        Appender!(ubyte[]) buf;
        buf.put(kindTag(node.kind));
        buf.put(encodeU64(node.length));
        final switch (node.kind)
        {
        case NodeKind.page:
            buf.put(encodeU64(node.page.bytes.length));
            buf.put(node.page.bytes);
            break;
        case NodeKind.slice:
            buf.put(node.slice.base.data);
            buf.put(encodeU64(node.slice.offset));
            break;
        case NodeKind.concat:
            buf.put(encodeU64(node.concat.children.length));
            foreach (child; node.concat.children)
            {
                buf.put(child.data);
            }
            break;
        case NodeKind.delta:
            buf.put(node.delta.base.data);
            buf.put(encodeU64(node.delta.patches.length));
            foreach (patch; node.delta.patches)
            {
                buf.put(encodeU64(patch.offset));
                buf.put(encodeU64(patch.data.length));
                buf.put(patch.data);
            }
            break;
        }
        return buf.data.idup;
    }

    static const(ubyte)[] kindTag(NodeKind kind)
    {
        immutable ubyte[][4] tags = [
            cast(const(ubyte)[])"page",
            cast(const(ubyte)[])"slice",
            cast(const(ubyte)[])"concat",
            cast(const(ubyte)[])"delta",
        ];
        return tags[cast(size_t)kind];
    }

    static ubyte[8] encodeU64(size_t value)
    {
        ubyte[8] buf;
        ulong val = cast(ulong)value;
        foreach (idx; 0 .. 8)
        {
            size_t shift = (7 - idx) * 8;
            buf[idx] = cast(ubyte)((val >> shift) & 0xFF);
        }
        return buf;
    }

    ByteSlice readConcat(const scope HashBytes[] children, size_t offset, size_t length)
    {
        size_t remaining = length;
        size_t currentOffset = offset;
        Appender!(ubyte[]) buffer;
        buffer.reserve(length);
        foreach (child; children)
        {
            auto childLen = nodeLength(child);
            if (currentOffset >= childLen)
            {
                currentOffset -= childLen;
                continue;
            }
            auto take = min(childLen - currentOffset, remaining);
            buffer.put(readSpan(child, currentOffset, take));
            remaining -= take;
            currentOffset = 0;
            if (remaining == 0)
            {
                break;
            }
        }
        enforce(remaining == 0, "requested span extends beyond concat length");
        return buffer.data.idup;
    }

    ByteSlice readDelta(const scope DeltaPayload payload, size_t offset, size_t length)
    {
        auto base = readSpan(payload.base, offset, length);
        auto buffer = base.dup;
        auto viewStart = offset;
        auto viewEnd = offset + length;
        foreach (patch; payload.patches)
        {
            auto patchStart = max(patch.offset, viewStart);
            auto patchEnd = min(patch.offset + patch.data.length, viewEnd);
            if (patchStart >= patchEnd)
            {
                continue;
            }
            auto baseStart = patchStart - viewStart;
            auto dataStart = patchStart - patch.offset;
            auto span = patchEnd - patchStart;
            buffer[baseStart .. baseStart + span] = patch.data[dataStart .. dataStart + span];
        }
        return cast(ByteSlice)buffer;
    }
}

struct CapabilityRecord
{
    string label;
    HashBytes hash;
}

struct CapabilityAnchor
{
    private VmoStore _store;
    private size_t _id;

    this(VmoStore store, size_t id)
    {
        _store = store;
        _id = id;
    }

    @property bool valid() const
    {
        return _store !is null;
    }

    void update(VmoHandle handle)
    {
        enforce(valid, "capability anchor no longer active");
        enforce(handle.store is _store, "cannot update anchor with foreign handle");
        _store.updateCapabilityRoot(_id, handle.hash);
    }

    void clear()
    {
        if (!valid)
        {
            return;
        }
        _store.unregisterCapabilityRoot(_id);
        _store = null;
    }
}

struct VmoPinLease
{
    private VmoStore _store;
    private HashBytes _hash;
    private bool _active;

    this(VmoStore store, HashBytes hash)
    {
        _store = store;
        _hash = hash;
        _active = true;
    }

    @disable this(this);

    @property bool active() const
    {
        return _active;
    }

    void release()
    {
        if (!_active)
        {
            return;
        }
        _store.releasePin(_hash);
        _active = false;
    }

    ~this()
    {
        release();
    }
}

/// Helper to build delta patches from arbitrary byte slices.
DeltaPatch makePatch(size_t offset, const scope ubyte[] data)
{
    return DeltaPatch(offset, data.idup);
}

HashBytes contentId(VmoHandle handle)
{
    return handle.hash;
}

VmoHandle swap(ref shared(VmoHandle) slot, VmoHandle newCap)
{
    auto previous = atomicExchange(slot, newCap);
    return cast(VmoHandle)previous;
}

/// Implements the "versioned pointer" pattern where an application holds a
/// capability to a pointer that always references the latest immutable VMO
/// snapshot.  Writers build a new snapshot, then attempt to publish it via a
/// compare-and-swap so readers never block.
struct VersionedVmoPointer
{
public:
    this(VmoHandle initial)
    {
        enforce(initial.store !is null, "initial handle must originate from a VmoStore");
        _store = initial.store;
        atomicStore(_current, initial);
    }

    @property bool initialized() const
    {
        return _store !is null;
    }

    @property VmoStore store() const
    {
        return _store;
    }

    /// Returns the latest committed snapshot.
    VmoHandle current() const
    {
        ensureInitialized();
        return cast(VmoHandle)atomicLoad(_current);
    }

    /// Atomically swaps the pointer with `next`, returning the previous
    /// snapshot.  Primarily useful for rollbacks/restores.
    VmoHandle exchange(VmoHandle next)
    {
        ensureInitialized();
        enforce(next.store is _store, "cannot install handle from a different VmoStore");
        return swap(_current, next);
    }

    /// Publishes `desired` if the current snapshot matches `expected`.
    bool compareAndSwap(VmoHandle expected, VmoHandle desired)
    {
        ensureInitialized();
        enforce(desired.store is _store, "cannot install handle from a different VmoStore");
        auto observed = atomicCompareExchange(_current, desired, expected);
        return observed == expected;
    }

    /// Convenience helper that commits a builder and attempts to publish the
    /// resulting snapshot if the pointer still matches `expected`.  Returns true
    /// when the publish succeeds.  When the publish fails the caller retains the
    /// committed handle (exposed via `result` when provided) and can decide how
    /// to reconcile the conflict.
    bool tryPublish(VmoHandle expected,
                    VBuilder builder,
                    VmoCommitMetadata metadata = VmoCommitMetadata.init,
                    VmoCommitResult* result = null)
    {
        ensureInitialized();
        auto commit = builder.commit(metadata);
        if (result !is null)
        {
            *result = commit;
        }
        enforce(commit.handle.store is _store, "cannot install handle from a different VmoStore");
        auto observed = atomicCompareExchange(_current, commit.handle, expected);
        return observed == expected;
    }

    /// Builds a delta VMO that describes how to transform the current snapshot
    /// into `candidate`.  The resulting overlay can be replicated elsewhere and
    /// applied lazily, making incremental updates efficient.
    VmoHandle diffAgainstCurrent(VmoHandle candidate)
    {
        ensureInitialized();
        enforce(candidate.store is _store, "diff requires handles from the same VmoStore");
        auto snapshot = current();
        return _store.diff(snapshot, candidate);
    }

private:
    VmoStore _store;
    shared(VmoHandle) _current;

    void ensureInitialized() const
    {
        enforce(initialized, "versioned pointer has not been initialised");
    }
}

class VmoChannel
{
public:
    void enqueue(const scope VmoHandle[] caps)
    {
        VmoHandle[] snapshot;
        snapshot.reserve(caps.length);
        foreach (cap; caps)
        {
            snapshot ~= cap;
        }
        _queue ~= snapshot;
    }

    VmoHandle[] receive()
    {
        enforce(_queue.length > 0, "channel queue empty");
        auto message = _queue[0];
        _queue = _queue[1 .. $];
        return message;
    }

    bool empty() const
    {
        return _queue.length == 0;
    }

private:
    VmoHandle[][] _queue;
}

void send(VmoChannel channel, const scope VmoHandle[] caps)
{
    enforce(channel !is null, "channel cannot be null");
    channel.enqueue(caps);
}

/// Simple in-memory filesystem that surfaces every directory entry as a VMO
/// capability.  Callers either publish existing `VmoHandle`s or let the
/// filesystem materialise handles from raw bytes.  Reading a file returns the
/// capability instead of copying data, mirroring the "filesystem returns VMO
/// capabilities" model described in the design notes.
class VmoFileSystem
{
public:
    this(VmoStore store)
    {
        enforce(store !is null, "store cannot be null");
        _store = store;
    }

    VmoHandle publishBytes(string path, const scope ubyte[] data)
    {
        enforce(path.length > 0, "path cannot be empty");
        auto handle = _store.fromBytes(data);
        return publish(path, handle);
    }

    VmoHandle publish(string path, VmoHandle handle)
    {
        enforce(path.length > 0, "path cannot be empty");
        _entries[path] = handle;
        return handle;
    }

    VmoHandle read(string path) const
    {
        auto ptr = path in _entries;
        enforce(ptr !is null, "missing file");
        return *ptr;
    }

    bool exists(string path) const
    {
        return (path in _entries) !is null;
    }

private:
    VmoStore _store;
    VmoHandle[string] _entries;
}

/// IPC endpoint helper that forwards VMO handles between processes.  Payloads
/// are delivered as handles so receivers can map the bytes read-only without
/// copying, satisfying the zero-copy IPC goal from the specification.
class VmoIpcEndpoint
{
public:
    this(VmoChannel channel)
    {
        enforce(channel !is null, "channel cannot be null");
        _channel = channel;
    }

    void sendPayload(const scope VmoHandle[] payload)
    {
        send(_channel, payload);
    }

    VmoHandle[] receivePayload()
    {
        return _channel.receive();
    }

    static VmoMapping[] mapReadOnly(const scope VmoHandle[] payload,
                                    NumaPlacementHint hint = NumaPlacementHint.automatic())
    {
        VmoMapping[] mappings;
        mappings.reserve(payload.length);
        foreach (handle; payload)
        {
            mappings ~= handle.map(0, MappingProt.read, hint);
        }
        return mappings;
    }

private:
    VmoChannel _channel;
}

enum PipeMode : ubyte
{
    chunked,
    rolling,
}

/// Pipe/stream abstraction that emits either a sequence of small VMOs or a
/// single rolling VMO backed by a `VBuilder`.  Writers append bytes and the pipe
/// exposes the resulting VMO handles to readers without any intermediate
/// buffers.
class VmoPipe
{
public:
    this(VmoStore store, PipeMode mode = PipeMode.chunked, size_t chunkSize = 4096)
    {
        enforce(store !is null, "store cannot be null");
        enforce(chunkSize > 0, "chunk size must be positive");
        _store = store;
        _mode = mode;
        _chunkSize = chunkSize;
        _channel = new VmoChannel();
        if (_mode == PipeMode.rolling)
        {
            _builder = _store.streamingBuilder();
        }
    }

    void write(const scope ubyte[] data)
    {
        if (data.length == 0)
        {
            return;
        }
        final switch (_mode)
        {
        case PipeMode.chunked:
            writeChunked(data);
            break;
        case PipeMode.rolling:
            enforce(_builder !is null, "rolling builder is unavailable");
            _builder.append(data);
            break;
        }
    }

    void flushRolling(VmoCommitMetadata metadata = VmoCommitMetadata.init)
    {
        enforce(_mode == PipeMode.rolling, "flushRolling only valid in rolling mode");
        enforce(_builder !is null, "rolling builder is unavailable");
        auto result = _builder.commit(metadata);
        send(_channel, [result.handle]);
        _builder = _store.streamingBuilder();
    }

    VmoHandle read()
    {
        auto message = _channel.receive();
        enforce(message.length == 1, "pipe messages contain exactly one VMO");
        return message[0];
    }

    bool empty() const
    {
        return _channel.empty();
    }

private:
    VmoStore _store;
    PipeMode _mode;
    size_t _chunkSize;
    VmoChannel _channel;
    VBuilder _builder;

    void writeChunked(const scope ubyte[] data)
    {
        size_t start = 0;
        while (start < data.length)
        {
            auto end = min(start + _chunkSize, data.length);
            auto handle = _store.fromBytes(data[start .. end]);
            send(_channel, [handle]);
            start = end;
        }
    }
}

/// Thin wrapper over a VMO-backed file that provides read-only mappings and
/// instant snapshots.  Taking a snapshot simply returns the underlying handle
/// because files are immutable VMOs.
struct MemoryMappedFile
{
    VmoHandle handle;

    this(VmoHandle handle)
    {
        this.handle = handle;
    }

    VmoMapping mapReadOnly(size_t address = 0,
                           NumaPlacementHint hint = NumaPlacementHint.automatic()) const
    {
        return handle.map(address, MappingProt.read, hint);
    }

    VmoHandle snapshot() const
    {
        return handle;
    }
}

unittest
{
    auto store = new VmoStore(8);
    auto data = cast(const ubyte[])"ABCDEFGH";
    auto handleA = store.page(data);
    auto handleB = store.page(data);
    assert(handleA.hash == handleB.hash);
    assert(store.nodeCount == 1);
    auto page = handleA.materializePage(0);
    assert(page == data);
    assert(store.uniquePageCount == 1);
}

unittest
{
    auto store = new VmoStore(8);
    auto base = store.fromBytes(cast(const ubyte[])"0123456789abcdef");
    auto left = store.slice(base, 0, 8);
    auto right = store.slice(base, 8, 8);
    auto joined = store.concat([right, left]);
    assert(joined.length == 16);
    assert(joined.materialize() == cast(const ubyte[])"89abcdef01234567");
}

unittest
{
    auto store = new VmoStore(8);
    auto base = store.fromBytes(cast(const ubyte[])"abcdefgh");
    DeltaPatch[] patches = [
        makePatch(2, cast(const ubyte[])"XYZ"),
        makePatch(6, cast(const ubyte[])"!!"),
    ];
    auto deltaHandle = store.delta(base, patches);
    assert(deltaHandle.materialize() == cast(const ubyte[])"abXYZf!!");
}

unittest
{
    auto store = new VmoStore(4);
    auto base = store.fromBytes(cast(const ubyte[])"AAAABBBB");
    auto combined = store.concat([base, base]);
    auto first = combined.materializePage(0);
    auto second = combined.materializePage(1);
    auto third = combined.materializePage(2);
    assert(first == third);
    assert(store.uniquePageCount == 2);
    assert(first.ptr is third.ptr);
    assert(second !is first);
}

unittest
{
    auto store = new VmoStore(4);
    auto handle = store.fromBytes(cast(const ubyte[])"abcdefghijkl");
    PageEntry[] pages;
    foreach (entry; handle.iterPages())
    {
        pages ~= entry;
    }
    assert(pages.length == 3);
    assert(pages[0].index == 0 && pages[0].data == cast(const ubyte[])"abcd");
    assert(pages[1].index == 1 && pages[1].data == cast(const ubyte[])"efgh");
    assert(pages[2].index == 2 && pages[2].data == cast(const ubyte[])"ijkl");
}

unittest
{
    auto store = new VmoStore(4);
    auto builder = store.boundedBuilder(8);
    builder.append(cast(const ubyte[])"abcd");
    builder.append(cast(const ubyte[])"efgh");
    auto result = builder.commit();
    auto handle = result.handle;
    assert(handle.length == 8);
    assert(handle.materialize() == cast(const ubyte[])"abcdefgh");
    assert(result.hash == handle.hash);
}

unittest
{
    import std.exception : assertThrown;
    auto store = new VmoStore(4);
    auto builder = store.boundedBuilder(4);
    builder.append(cast(const ubyte[])"abcd");
    assertThrown!Exception(builder.append(cast(const ubyte[])"e"));
}

unittest
{
    import std.exception : assertThrown;
    auto store = new VmoStore(4);
    auto builder = store.streamingBuilder();
    builder.append(cast(const ubyte[])"abcd");
    builder.append(cast(const ubyte[])"efgh");
    builder.patch(2, cast(const ubyte[])"XYZ");
    auto result = builder.commit();
    auto handle = result.handle;
    assert(handle.materialize() == cast(const ubyte[])"abXYZfgh");
    assertThrown!Exception(builder.commit());
    assertThrown!Exception(builder.append(cast(const ubyte[])"zz"));
}

unittest
{
    auto store = new VmoStore(4);
    auto builder = store.createBuilder(0);
    builder.append(cast(const ubyte[])"abcd");
    builder.write(4, cast(const ubyte[])"ef");
    builder.write(0, cast(const ubyte[])"AB");
    auto result = builder.commit();
    assert(result.handle.materialize() == cast(const ubyte[])"ABcdef");
}

unittest
{
    auto store = new VmoStore(4);
    auto builder = store.createBuilder(6);
    builder.append(cast(const ubyte[])"abcdef");
    auto source = store.fromBytes(cast(const ubyte[])"UVWXYZ");
    builder.copyFrom(source, 3, 3, 3);
    auto result = builder.commit();
    assert(result.handle.materialize() == cast(const ubyte[])"abcXYZ");
}

unittest
{
    auto store = new VmoStore(4);
    auto base = store.fromBytes(cast(const ubyte[])"ABCDEFGH");
    auto updated = store.fromBytes(cast(const ubyte[])"ABcdEFGH");
    auto delta = store.diff(base, updated);
    assert(delta.materialize() == updated.materialize());
}

unittest
{
    auto store = new VmoStore(4);
    auto handle = store.fromBytes(cast(const ubyte[])"abcd");
    auto mapping = handle.map(0, MappingProt.read);
    assert(mapping.handle.hash == handle.hash);
    assert(mapping.prot == MappingProt.read);
}

unittest
{
    auto store = new VmoStore(4);
    auto handle = store.fromBytes(cast(const ubyte[])"abcd");
    auto hint = NumaPlacementHint.prefer(NumaNode.node2);
    auto mapping = handle.map(0, MappingProt.read, hint);
    assert(mapping.numaHint.hasPreference);
    assert(mapping.numaHint.preferred == NumaNode.node2);
}

unittest
{
    auto store = new VmoStore(4);
    auto first = store.fromBytes(cast(const ubyte[])"abcd");
    auto second = store.fromBytes(cast(const ubyte[])"efgh");
    shared(VmoHandle) slot;
    atomicStore(slot, first);
    auto previous = swap(slot, second);
    assert(previous.hash == first.hash);
}

unittest
{
    auto store = new VmoStore(4);
    auto builder = store.createBuilder(4);
    builder.append(cast(const ubyte[])"INIT");
    auto base = builder.commit().handle;
    VersionedVmoPointer pointer = VersionedVmoPointer(base);
    assert(pointer.initialized());

    auto snapshot = pointer.current();
    auto writerA = store.createBuilder(4);
    writerA.append(cast(const ubyte[])"AAAA");
    auto updateA = writerA.commit().handle;
    assert(pointer.compareAndSwap(snapshot, updateA));
    auto latest = pointer.current();
    assert(latest.materialize() == cast(const ubyte[])"AAAA");

    auto writerB = store.createBuilder(4);
    writerB.append(cast(const ubyte[])"BBBB");
    auto updateB = writerB.commit().handle;
    assert(!pointer.compareAndSwap(snapshot, updateB));
    auto delta = pointer.diffAgainstCurrent(updateB);
    assert(delta.materialize() == updateB.materialize());

    VmoCommitResult publishResult;
    auto writerC = store.createBuilder(4);
    writerC.append(cast(const ubyte[])"CCCC");
    assert(pointer.tryPublish(latest, writerC, VmoCommitMetadata.init, &publishResult));
    assert(pointer.current().materialize() == cast(const ubyte[])"CCCC");
    latest = pointer.current();

    auto rollback = store.fromBytes(cast(const ubyte[])"ROLL");
    auto replaced = pointer.exchange(rollback);
    assert(replaced.hash == latest.hash);
    assert(pointer.current().hash == rollback.hash);
}

unittest
{
    auto store = new VmoStore(4);
    auto channel = new VmoChannel();
    auto payloadA = store.fromBytes(cast(const ubyte[])"abcd");
    auto payloadB = store.fromBytes(cast(const ubyte[])"efgh");
    send(channel, [payloadA, payloadB]);
    auto received = channel.receive();
    assert(received.length == 2);
    assert(received[0].hash == payloadA.hash);
    assert(received[1].hash == payloadB.hash);
}

unittest
{
    auto store = new VmoStore(8);
    auto fs = new VmoFileSystem(store);
    auto handle = fs.publishBytes("/cfg", cast(const ubyte[])"CONFIG");
    auto reopened = fs.read("/cfg");
    assert(handle.hash == reopened.hash);
    assert(fs.exists("/cfg"));
}

unittest
{
    auto store = new VmoStore(8);
    auto channel = new VmoChannel();
    auto endpoint = new VmoIpcEndpoint(channel);
    auto payload = store.fromBytes(cast(const ubyte[])"payload");
    endpoint.sendPayload([payload]);
    auto received = endpoint.receivePayload();
    auto mappings = VmoIpcEndpoint.mapReadOnly(received);
    assert(mappings.length == 1);
    assert(mappings[0].handle.hash == payload.hash);
}

unittest
{
    auto store = new VmoStore(4);
    auto pipe = new VmoPipe(store, PipeMode.chunked, 2);
    pipe.write(cast(const ubyte[])"abcd");
    auto first = pipe.read();
    auto second = pipe.read();
    assert(first.materialize() == cast(const ubyte[])"ab");
    assert(second.materialize() == cast(const ubyte[])"cd");
    assert(pipe.empty());
}

unittest
{
    auto store = new VmoStore(4);
    auto pipe = new VmoPipe(store, PipeMode.rolling);
    pipe.write(cast(const ubyte[])"ab");
    pipe.write(cast(const ubyte[])"cd");
    pipe.flushRolling();
    auto combined = pipe.read();
    assert(combined.materialize() == cast(const ubyte[])"abcd");
}

unittest
{
    auto store = new VmoStore(4);
    auto handle = store.fromBytes(cast(const ubyte[])"file");
    MemoryMappedFile file = MemoryMappedFile(handle);
    auto mapping = file.mapReadOnly();
    assert(mapping.handle.hash == handle.hash);
    auto snapshot = file.snapshot();
    assert(snapshot.hash == handle.hash);
}

unittest
{
    auto store = new VmoStore(4, 2);
    auto live = store.fromBytes(cast(const ubyte[])"live");
    auto garbage = store.fromBytes(cast(const ubyte[])"dead");
    auto anchor = store.trackCapability("process:1", live);
    store.collectGarbage();
    assert(store.contains(live.hash));
    assert(!store.contains(garbage.hash));

    auto updated = store.fromBytes(cast(const ubyte[])"next");
    anchor.update(updated);
    store.collectGarbage();
    assert(!store.contains(live.hash));
    assert(store.contains(updated.hash));

    anchor.clear();
    store.collectGarbage();
    assert(store.nodeCount == 0);
}

unittest
{
    auto store = new VmoStore(4, 2);
    auto pinned = store.fromBytes(cast(const ubyte[])"keep");
    auto lease = store.pin(pinned);
    store.collectGarbage();
    assert(store.contains(pinned.hash));
    lease.release();
    store.collectGarbage();
    assert(store.nodeCount == 0);
}

unittest
{
    auto store = new VmoStore(4, 2);
    auto first = store.fromBytes(cast(const ubyte[])"aaaa");
    auto second = store.fromBytes(cast(const ubyte[])"bbbb");
    auto third = store.fromBytes(cast(const ubyte[])"cccc");
    first.materialize();
    second.materialize();
    assert(store.uniquePageCount == 2);
    third.materialize();
    assert(store.uniquePageCount == 2);
    // Accessing an evicted entry re-populates the cache without exceeding capacity.
    second.materialize();
    assert(store.uniquePageCount == 2);
}
