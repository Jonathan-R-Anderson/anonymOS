module distributed_fs.fs.storage;

import distributed_fs.storage :
    storeBlockWrapper, getBlockWrapper,
    initDhtStore, initLocalStore;
import distributed_fs.fs.node;
import std.array;
import std.conv : to;
import std.digest.crc : crc32Of;

enum BLOCK_SIZE = 4096;

struct RaidStripe {
    string[] dataIds;
    string parityId;
}

/// store a file's data using simple RAID5-style parity across the selected backend
void writeFile(FileNode file, const(ubyte)[] data) {
    // no stateful CRC needed
    size_t blocks = (data.length + BLOCK_SIZE - 1) / BLOCK_SIZE;
    foreach(i; 0 .. blocks) {
        size_t off = i * BLOCK_SIZE;
        auto slice = data[off .. off + BLOCK_SIZE > data.length ? data.length : off + BLOCK_SIZE];
        auto id = "block" ~ to!string(crc32Of(slice ~ cast(ubyte[])to!string(off)));
        storeBlockWrapper(id, slice);
        file.blockIds ~= id;
    }
}

/// read and rebuild file data
ubyte[] readFile(FileNode file) {
    ubyte[] result;
    foreach(id; file.blockIds) {
        auto blk = getBlockWrapper(id);
        if(blk.length)
            result ~= blk;
    }
    return result;
}

