module minimal_os.kernel.paging;

import std.array : appender, Appender;
import std.exception : enforce;
import minimal_os.kernel.numa : NumaNode, NumaPlacementHint;
import minimal_os.kernel.vmo : ByteSlice, HashBytes, VmoHandle, VmoStore;

struct PageCoordinate
{
    HashBytes object;
    size_t pageIndex;

    bool opEquals(const PageCoordinate rhs) const @safe pure nothrow
    {
        return pageIndex == rhs.pageIndex && object == rhs.object;
    }

    size_t toHash() const @safe pure nothrow
    {
        size_t hash = object.toHash();
        hash ^= pageIndex + 0x9e3779b97f4a7c15 + (hash << 6) + (hash >> 2);
        return hash;
    }
}

private struct PackedPage
{
    bool compressed;
    immutable(ubyte)[] storage;
    size_t plainLength;
}

private struct ResidentPage
{
    PageCoordinate coord;
    HashBytes contentHash;
    PackedPage packed;
    ByteSlice cachedPlain;
    ByteSlice[NumaNode] replicas;
}

/// Content-addressed page cache that keeps page frames keyed by the owning VMO
/// hash and page index. Frames are deduplicated by their content hash and may
/// be replicated to satisfy NUMA placement hints.
final class ContentAddressedPageCache
{
public:
    this(VmoStore store)
    {
        enforce(store !is null, "store cannot be null");
        _store = store;
    }

    @property size_t residentPageCount() const
    {
        return _frames.length;
    }

    /// Pins a VMO root, incrementing reachability counts for every node in its
    /// extent DAG.
    void pin(VmoHandle root)
    {
        adjustReachability(root.hash, +1);
    }

    /// Drops a VMO root. When a node transitions to zero reachability any
    /// cached page frames that belong to it are discarded.
    void unpin(VmoHandle root)
    {
        adjustReachability(root.hash, -1);
    }

    /// Returns a materialised page for the given VMO and page index. The
    /// returned slice respects NUMA placement hints, replicating data if the
    /// caller requests it.
    ByteSlice fault(VmoHandle handle, size_t pageIndex, NumaPlacementHint hint = NumaPlacementHint.automatic())
    {
        enforce(pageIndex * _store.pageSize < handle.length, "page index outside VMO extent");
        auto key = PageCoordinate(handle.hash, pageIndex);
        auto framePtr = key in _frames;
        if (framePtr is null)
        {
            framePtr = materializeFrame(handle, key);
        }
        return ensureReplica(*framePtr, hint);
    }

private:
    VmoStore _store;
    ResidentPage[PageCoordinate] _frames;
    size_t[HashBytes] _nodeRefCounts;

    ResidentPage* materializeFrame(VmoHandle handle, PageCoordinate key)
    {
        auto bytes = handle.materializePage(key.pageIndex);
        PackedPage packed = pack(bytes);
        ResidentPage page;
        page.coord = key;
        page.contentHash = HashBytes.fromBytes(bytes);
        page.packed = packed;
        _frames[key] = page;
        return key in _frames;
    }

    ByteSlice ensureReplica(ref ResidentPage page, NumaPlacementHint hint)
    {
        auto node = hint.resolvedNode();
        auto existing = node in page.replicas;
        if (existing !is null && (*existing).length != 0)
        {
            return *existing;
        }

        auto plain = ensurePlain(page);
        ByteSlice replica = hint.replicateReadOnly ? plain.idup : plain;
        page.replicas[node] = replica;
        auto stored = node in page.replicas;
        return *stored;
    }

    ByteSlice ensurePlain(ref ResidentPage page)
    {
        if (page.cachedPlain.length != 0)
        {
            return page.cachedPlain;
        }

        if (!page.packed.compressed)
        {
            page.cachedPlain = page.packed.storage;
            return page.cachedPlain;
        }

        auto decompressed = rleDecompress(page.packed.storage, page.packed.plainLength);
        page.cachedPlain = decompressed;
        return page.cachedPlain;
    }

    void adjustReachability(HashBytes root, int delta)
    {
        enforce(delta == 1 || delta == -1, "delta must be +/- 1");
        enforce(_store.contains(root), "root hash not recognised");
        HashBytes[] stack;
        stack ~= root;
        bool[HashBytes] visited;
        while (stack.length > 0)
        {
            auto current = stack[$ - 1];
            stack.length -= 1;
            if (auto flag = current in visited)
            {
                if (*flag)
                {
                    continue;
                }
            }
            visited[current] = true;
            auto countPtr = current in _nodeRefCounts;
            size_t previous = countPtr is null ? 0 : *countPtr;
            if (delta > 0)
            {
                auto updated = previous + 1;
                _nodeRefCounts[current] = updated;
            }
            else
            {
                enforce(countPtr !is null && previous > 0, "reachability underflow");
                auto updated = previous - 1;
                if (updated == 0)
                {
                    _nodeRefCounts.remove(current);
                    evictNode(current);
                }
                else
                {
                    _nodeRefCounts[current] = updated;
                }
            }

            foreach (child; _store.childHashes(current))
            {
                stack ~= child;
            }
        }
    }

    void evictNode(HashBytes node)
    {
        PageCoordinate[] victims;
        foreach (key, frame; _frames)
        {
            if (key.object == node)
            {
                victims ~= key;
            }
        }
        foreach (victim; victims)
        {
            _frames.remove(victim);
        }
    }

    static PackedPage pack(ByteSlice bytes)
    {
        PackedPage page;
        page.plainLength = bytes.length;
        auto compressed = rleCompress(bytes);
        if (compressed.length != 0)
        {
            page.compressed = true;
            page.storage = compressed;
        }
        else
        {
            page.compressed = false;
            page.storage = bytes.idup;
        }
        return page;
    }

    static ByteSlice rleDecompress(ByteSlice encoded, size_t expectedLength)
    {
        enforce((encoded.length & 1) == 0, "corrupt RLE page");
        auto buffer = new ubyte[expectedLength];
        size_t cursor = 0;
        size_t idx = 0;
        while (idx < encoded.length)
        {
            ubyte run = encoded[idx];
            ++idx;
            ubyte value = encoded[idx];
            ++idx;
            foreach (_; 0 .. run)
            {
                enforce(cursor < expectedLength, "RLE overrun");
                buffer[cursor++] = value;
            }
        }
        enforce(cursor == expectedLength, "RLE underrun");
        return buffer.idup;
    }

    static immutable(ubyte)[] rleCompress(ByteSlice data)
    {
        if (data.length < 8)
        {
            return immutable(ubyte)[].init;
        }
        Appender!(ubyte[]) buf;
        size_t idx = 0;
        while (idx < data.length)
        {
            ubyte value = data[idx];
            size_t run = 1;
            while (idx + run < data.length && data[idx + run] == value && run < 255)
            {
                ++run;
            }
            buf.put(cast(ubyte)run);
            buf.put(value);
            idx += run;
        }
        auto encoded = buf.data;
        if (encoded.length >= data.length)
        {
            return immutable(ubyte)[].init;
        }
        return encoded.idup;
    }
}

unittest
{
    auto store = new VmoStore(4);
    auto cache = new ContentAddressedPageCache(store);
    auto handle = store.fromBytes(cast(const ubyte[])"AAAABBBB");
    cache.pin(handle);
    auto a = cache.fault(handle, 0);
    auto b = cache.fault(handle, 0);
    assert(a.ptr is b.ptr);
    cache.unpin(handle);
    assert(cache.residentPageCount == 0);
}

unittest
{
    auto store = new VmoStore(4);
    auto cache = new ContentAddressedPageCache(store);
    auto base = store.fromBytes(cast(const ubyte[])"abcdEFGH");
    auto slice = store.slice(base, 0, base.length);
    cache.pin(slice);
    auto first = cache.fault(slice, 0, NumaPlacementHint.automatic());
    auto replica = cache.fault(slice, 0, NumaPlacementHint.replicate(NumaNode.node1));
    assert(first == replica);
    assert(first.ptr !is replica.ptr);
    cache.unpin(slice);
}
