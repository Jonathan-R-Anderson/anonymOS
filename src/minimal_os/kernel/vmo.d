module minimal_os.kernel.vmo;

import core.atomic : atomicExchange, atomicStore;
import std.algorithm : max, min, sort;
import std.array : appender, Appender;
import std.digest.sha : sha256Of;
import std.exception : enforce;
import minimal_os.kernel.numa : NumaNode, NumaPlacementHint;

alias ByteSlice = immutable(ubyte)[];

class VmoStore;
struct VmoHandle;
struct DeltaPatch;

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

class VmoStore
{
public:
    this(size_t pageSize = 4096)
    {
        enforce(pageSize > 0, "pageSize must be positive");
        _pageSize = pageSize;
    }

    @property size_t pageSize() const
    {
        return _pageSize;
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
            return *cached;
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
        _pageCache[key] = *pooled;
        return *pooled;
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
    ByteSlice[PageKey] _pageCache;
    ByteSlice[HashBytes] _pagePool;

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
    auto channel = new VmoChannel();
    auto payloadA = store.fromBytes(cast(const ubyte[])"abcd");
    auto payloadB = store.fromBytes(cast(const ubyte[])"efgh");
    send(channel, [payloadA, payloadB]);
    auto received = channel.receive();
    assert(received.length == 2);
    assert(received[0].hash == payloadA.hash);
    assert(received[1].hash == payloadB.hash);
}
