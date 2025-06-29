module distributed_fs.storage.local;

import std.file : mkdirRecurse, exists, read, write;
import std.path : buildPath;

string basePath;

/// Initialize simple disk-backed store
void initLocal(string path = "fs_data") {
    basePath = path;
    mkdirRecurse(basePath);
}

/// Store a block directly on disk
void storeLocal(string id, const(ubyte)[] data) {
    auto file = buildPath(basePath, id);
    write(file, data);
}

/// Retrieve a block from disk
ubyte[] getLocal(string id) {
    auto file = buildPath(basePath, id);
    if(exists(file))
        return cast(ubyte[])read(file);
    return null;
}
