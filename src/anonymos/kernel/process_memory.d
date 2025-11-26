module anonymos.kernel.process_memory;

import core.atomic : atomicLoad, atomicStore;
import std.exception : enforce;

import anonymos.kernel.vmo : VmoStore, VmoHandle, VBuilder, VmoCommitMetadata,
    VmoCommitResult, swap;

/// Describes the immutable code/static data, persistent heap snapshots, and the
/// ephemeral kernel stack that make up a process address space.
///
/// * Code/static segments are represented as immutable VMOs.  They are never
///   mutated in-place and therefore can be freely shared between processes.
/// * Heap allocations are staged through VMO builders and atomically published
///   so readers always see a consistent snapshot.
/// * Each thread receives an ephemeral kernel stack used as scratch storage
///   while running inside the kernel.  The stack is never directly shared; when
///   user visible state needs to cross a syscall or IPC boundary the content is
///   snapshotted into a VMO to preserve the "all user memory is VMO" invariant.
struct ProcessMemoryLayout
{
public:
    this(VmoStore store, VmoHandle codeSegment, size_t kernelStackCapacity = 16384)
    {
        enforce(store !is null, "store cannot be null");
        _store = store;
        code = codeSegment;
        heap = ProcessHeap(store);
        kernelStack = EphemeralKernelStack(store, kernelStackCapacity);
    }

    /// Convenience helper that forwards to the underlying heap so callers can
    /// start staging writes without reaching into the heap directly.
    VBuilder newHeapBuilder(size_t sizeHint = 0)
    {
        return heap.beginBuild(sizeHint);
    }

    /// Publishes the staged heap builder and returns the resulting immutable
    /// handle.  The commit is atomic so concurrent readers only see entire
    /// snapshots of the heap.
    VmoHandle publishHeap(VBuilder builder, VmoCommitMetadata metadata = VmoCommitMetadata.init)
    {
        auto result = heap.publish(builder, metadata);
        return result.handle;
    }

    /// Snapshots the ephemeral kernel stack into a VMO that can be recorded at
    /// syscall/IPC boundaries.
    VmoHandle snapshotKernelStack(VmoCommitMetadata metadata = VmoCommitMetadata.init)
    {
        return kernelStack.snapshot(metadata);
    }

    VmoHandle code;
    ProcessHeap heap;
    EphemeralKernelStack kernelStack;

private:
    VmoStore _store;
}

/// Manages the persistent heap snapshot for a process.  Callers stage mutations
/// through `VBuilder`s and atomically publish the resulting VMOs so observers
/// always see whole heaps.
struct ProcessHeap
{
public:
    this(VmoStore store)
    {
        enforce(store !is null, "store cannot be null");
        _store = store;
        const(ubyte)[] empty;
        auto initial = _store.fromBytes(empty);
        atomicStore(_root, initial);
    }

    @property VmoStore store() const
    {
        return _store;
    }

    /// Starts a new builder used to stage heap updates.
    VBuilder beginBuild(size_t sizeHint = 0)
    {
        return _store.createBuilder(sizeHint);
    }

    /// Atomically publishes the result of a builder commit.
    VmoCommitResult publish(VBuilder builder, VmoCommitMetadata metadata = VmoCommitMetadata.init)
    {
        auto result = builder.commit(metadata);
        atomicStore(_root, result.handle);
        return result;
    }

    /// Returns the most recently published heap snapshot.
    VmoHandle current() const
    {
        return cast(VmoHandle)atomicLoad(_root);
    }

    /// Performs a raw swap of the heap handle.  Useful for replacing the heap
    /// with a previously recorded snapshot.
    VmoHandle exchange(VmoHandle next)
    {
        enforce(next.length >= 0, "next heap handle cannot be null");
        return swap(_root, next);
    }

private:
    VmoStore _store;
    shared(VmoHandle) _root;
}

/// Represents the ephemeral kernel stack assigned to a thread.  The stack is
/// private to the kernel; snapshots are taken via `snapshot` when user visible
/// boundaries are crossed.
struct EphemeralKernelStack
{
public:
    this(VmoStore store, size_t capacity)
    {
        enforce(store !is null, "store cannot be null");
        enforce(capacity > 0, "stack capacity must be positive");
        _store = store;
        _buffer.length = capacity;
    }

    @property size_t capacity() const
    {
        return _buffer.length;
    }

    @property size_t used() const
    {
        return _used;
    }

    /// Appends scratch data onto the stack.  This is intended to be used by
    /// kernel subsystems that need temporary storage while servicing a call.
    void push(const scope ubyte[] data)
    {
        if (data.length == 0)
        {
            return;
        }
        enforce(_used + data.length <= _buffer.length, "kernel stack overflow");
        _buffer[_used .. _used + data.length] = data[];
        _used += data.length;
    }

    /// Releases the last `bytes` written to the stack.
    void pop(size_t bytes)
    {
        enforce(bytes <= _used, "pop exceeds current stack usage");
        _used -= bytes;
    }

    /// Clears the stack without touching the underlying buffer contents.
    void reset()
    {
        _used = 0;
    }

    /// Captures the current stack content inside an immutable VMO.  The stack
    /// remains private — only the snapshot handle is shareable.
    VmoHandle snapshot(VmoCommitMetadata metadata = VmoCommitMetadata.init)
    {
        auto builder = _store.createBuilder(_used == 0 ? 0 : _used);
        if (_used > 0)
        {
            builder.append(_buffer[0 .. _used]);
        }
        auto result = builder.commit(metadata);
        return result.handle;
    }

    /// Restores stack contents from a previously snapshotted VMO.  Useful when
    /// the kernel needs to reinstate user visible state.
    void restore(VmoHandle snapshot)
    {
        auto bytes = snapshot.materialize();
        enforce(bytes.length <= _buffer.length, "snapshot larger than stack capacity");
        _buffer[0 .. bytes.length] = bytes[];
        _used = bytes.length;
    }

private:
    VmoStore _store;
    ubyte[] _buffer;
    size_t _used;
}

unittest
{
    auto store = new VmoStore(4);
    ProcessHeap heap = ProcessHeap(store);
    auto builder = heap.beginBuild(4);
    builder.append(cast(const ubyte[])"HEAP");
    auto result = heap.publish(builder);
    assert(result.handle.materialize() == cast(const ubyte[])"HEAP");
    assert(heap.current().hash == result.handle.hash);
}

unittest
{
    auto store = new VmoStore(8);
    EphemeralKernelStack stack = EphemeralKernelStack(store, 32);
    stack.push(cast(const ubyte[])"stack frame");
    auto snapshot = stack.snapshot();
    assert(snapshot.materialize() == cast(const ubyte[])"stack frame");
    stack.reset();
    assert(stack.used == 0);
    stack.restore(snapshot);
    assert(stack.used == cast(const(ubyte)[])"stack frame".length);
}

unittest
{
    auto store = new VmoStore(8);
    auto code = store.fromBytes(cast(const ubyte[])"code-segment");
    ProcessMemoryLayout layout = ProcessMemoryLayout(store, code, 32);
    auto builder = layout.newHeapBuilder(4);
    builder.append(cast(const ubyte[])"data");
    auto published = layout.publishHeap(builder);
    assert(published.materialize() == cast(const ubyte[])"data");
    auto stackSnapshot = layout.snapshotKernelStack();
    assert(stackSnapshot.length == 0);
    assert(layout.code.hash == code.hash);
}
