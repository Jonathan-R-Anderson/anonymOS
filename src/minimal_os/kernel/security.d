module minimal_os.kernel.security;

import std.algorithm : sort;
import std.array : appender;
import std.conv : to;
import std.exception : enforce;
import std.exception : EnforceException;

import minimal_os.kernel.numa : NumaPlacementHint;
import minimal_os.kernel.vmo : HashBytes, MappingProt, VBuilder, VmoCommitMetadata,
    VmoCommitResult, VmoHandle, VmoMapping, VmoStore;

/// Enumerates the verbs that a capability can exercise over a `VmoHandle`.
enum CapabilityRight : ubyte
{
    mapView,
    deriveView,
}

/// Wraps a `VmoHandle` together with an explicit list of capability rights.
/// Only callers that hold the capability can map the underlying VMO or derive
/// additional views, mirroring the object-capability discipline described in
/// the kernel design notes.
struct VmoCapability
{
public:
    this(VmoHandle handle, const scope CapabilityRight[] rights = null)
    {
        enforce(handle.store !is null, "capabilities require handles allocated from a VmoStore");
        _handle = handle;
        if (rights.length == 0)
        {
            // Default to the most common read-only verbs.
            _rights = [CapabilityRight.mapView, CapabilityRight.deriveView];
            return;
        }
        foreach (right; rights)
        {
            addRight(right);
        }
        enforce(_rights.length > 0, "capabilities must include at least one right");
    }

    @property VmoHandle handle() const
    {
        return _handle;
    }

    /// Returns true when the capability contains the requested right.
    bool hasRight(CapabilityRight right) const
    {
        foreach (candidate; _rights)
        {
            if (candidate == right)
            {
                return true;
            }
        }
        return false;
    }

    /// Creates a new read-only mapping using the underlying `VmoHandle`.  The
    /// call fails if the capability does not include the `mapView` right.
    VmoMapping mapReadOnly(size_t address = 0,
                           NumaPlacementHint hint = NumaPlacementHint.automatic()) const
    {
        ensureRight(CapabilityRight.mapView, "map");
        return _handle.map(address, MappingProt.read, hint);
    }

    /// Derives a new capability for a slice of the current VMO.  Callers can
    /// optionally specify a list of rights for the derived capability; the
    /// requested rights must be a subset of the parent's rights.  Leaving the
    /// list empty causes the derived capability to inherit the parent's verb
    /// set.
    VmoCapability deriveView(size_t offset,
                             size_t length,
                             const scope CapabilityRight[] childRights = null) const
    {
        ensureRight(CapabilityRight.deriveView, "derive");
        auto derived = _handle.store.slice(_handle, offset, length);
        CapabilityRight[] normalized;
        if (childRights.length == 0)
        {
            normalized = _rights;
        }
        else
        {
            normalized = childRights.dup;
        }
        enforce(canGrant(normalized), "cannot grant rights that are not held by the parent capability");
        return VmoCapability(derived, normalized);
    }

private:
    VmoHandle _handle;
    CapabilityRight[] _rights;

    void ensureRight(CapabilityRight right, string operation) const
    {
        enforce(hasRight(right), "capability missing right required to " ~ operation);
    }

    void addRight(CapabilityRight right)
    {
        if (hasRight(right))
        {
            return;
        }
        _rights ~= right;
    }

    bool canGrant(const scope CapabilityRight[] requested) const
    {
        foreach (right; requested)
        {
            if (!hasRight(right))
            {
                return false;
            }
        }
        return true;
    }
}

/// Thin wrapper around `VBuilder` that emphasises the staged-write pattern.
/// Callers append or patch bytes through the builder and can only observe the
/// resulting immutable snapshot once `seal` returns, guaranteeing that there is
/// no ambient writable mapping.
final class StagedVmoWriter
{
public:
    this(VBuilder builder)
    {
        enforce(builder !is null, "writer requires a valid builder");
        _builder = builder;
    }

    void append(const scope ubyte[] bytes)
    {
        _builder.append(bytes);
    }

    void write(size_t offset, const scope ubyte[] bytes)
    {
        _builder.write(offset, bytes);
    }

    void patch(size_t offset, const scope ubyte[] bytes)
    {
        _builder.patch(offset, bytes);
    }

    SealedCommit seal(VmoCommitMetadata metadata = VmoCommitMetadata.init)
    {
        auto result = _builder.commit(metadata);
        return SealedCommit(result);
    }

    @property size_t length() const
    {
        return _builder.length;
    }

private:
    VBuilder _builder;
}

/// Captures the immutable output of a `VBuilder` commit along with a
/// deterministic provenance digest.  The digest encodes the content hash,
/// length, and metadata tags in a canonical order so auditors can replay commits
/// without access to the original builder state.
struct SealedCommit
{
public:
    this(VmoCommitResult result)
    {
        handle = result.handle;
        contentHash = result.hash;
        length = result.length;
        metadata = result.metadata;
        provenanceDigest = canonicalProvenance();
    }

    /// Returns true when another recording was derived from the exact same
    /// content and metadata.
    bool matches(const scope SealedCommit other) const
    {
        return provenanceDigest == other.provenanceDigest;
    }

    /// Confirms that a `VmoHandle` still references the snapshot that produced
    /// this commit.
    bool matchesHandle(VmoHandle candidate) const
    {
        return candidate.hash == contentHash;
    }

    HashBytes handleHash() const
    {
        return contentHash;
    }

private:
    HashBytes canonicalProvenance() const
    {
        string[] keys;
        keys.reserve(metadata.tags.length);
        foreach (key, _; metadata.tags)
        {
            keys ~= key;
        }
        sort(keys);

        auto builder = appender!string();
        builder.put("len=");
        builder.put(to!string(length));
        builder.put(";hash=");
        builder.put(hashToHex(contentHash));
        foreach (key; keys)
        {
            builder.put(";");
            builder.put(key);
            builder.put("=");
            builder.put(metadata.tags[key]);
        }
        auto canonical = builder.data;
        auto bytes = cast(const(ubyte)[])canonical;
        return HashBytes.fromBytes(bytes);
    }

    static string hashToHex(HashBytes hash)
    {
        immutable(char)[16] alphabet = "0123456789abcdef";
        char[HashBytes.sizeof * 2] buffer;
        foreach (idx, byteVal; hash.data)
        {
            buffer[idx * 2] = alphabet[byteVal >> 4];
            buffer[idx * 2 + 1] = alphabet[byteVal & 0x0F];
        }
        return buffer[].idup;
    }

public:
    VmoHandle handle;
    HashBytes contentHash;
    size_t length;
    VmoCommitMetadata metadata;
    HashBytes provenanceDigest;
}

unittest
{
    import std.exception : assertThrown;

    auto store = new VmoStore();
    auto builder = store.boundedBuilder(8);
    builder.append(cast(ubyte[])"security");
    auto commit = builder.commit();
    auto cap = VmoCapability(commit.handle, [CapabilityRight.mapView, CapabilityRight.deriveView]);
    auto mapping = cap.mapReadOnly();
    assert(mapping.prot == MappingProt.read);

    auto derived = cap.deriveView(0, 3, [CapabilityRight.mapView]);
    assert(derived.handle.length == 3);

    auto readOnly = VmoCapability(commit.handle, [CapabilityRight.mapView]);
    assertThrown!EnforceException(readOnly.deriveView(0, 1));
}

unittest
{
    auto store = new VmoStore();
    auto writer = new StagedVmoWriter(store.streamingBuilder());
    writer.append(cast(ubyte[])"log");
    writer.append(cast(ubyte[])"book");
    VmoCommitMetadata metadata;
    metadata.tags["author"] = "ci";
    auto sealed = writer.seal(metadata);
    assert(sealed.handleHash() == sealed.handle.hash);
    assert(sealed.matchesHandle(sealed.handle));
}

unittest
{
    auto store = new VmoStore();

    VmoCommitMetadata first;
    first.tags["op"] = "commit";
    first.tags["user"] = "alice";

    VmoCommitMetadata second;
    second.tags["user"] = "alice";
    second.tags["op"] = "commit";

    auto builderA = store.boundedBuilder(4);
    builderA.append(cast(ubyte[])"data");
    auto commitA = SealedCommit(builderA.commit(first));

    auto builderB = store.boundedBuilder(4);
    builderB.append(cast(ubyte[])"data");
    auto commitB = SealedCommit(builderB.commit(second));

    assert(commitA.matches(commitB));
}
