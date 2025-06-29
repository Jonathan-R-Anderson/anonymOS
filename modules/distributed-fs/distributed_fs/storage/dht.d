module distributed_fs.storage.dht;

import std.stdio;
import std.string;
import std.file : mkdirRecurse, exists, dirEntries, read, write, SpanMode;
import std.path : buildPath, baseName;
import std.conv : to;

/// Simple in-memory DHT used for examples.
struct Dht {
    // vector of node tables mapping id -> data
    private ubyte[][string][] nodes;
    size_t redundancy;
    string basePath;

    this(size_t nodeCount, size_t redundancy, string path) {
        nodes.length = nodeCount;
        foreach(i; 0 .. nodeCount) {
            nodes[i] = ubyte[][string].init;
        }
        this.redundancy = redundancy;
        this.basePath = path;
        mkdirRecurse(basePath);
        foreach(i; 0 .. nodeCount) {
            auto dir = buildPath(basePath, "node" ~ to!string(i));
            mkdirRecurse(dir);
            if (exists(dir)) {
                foreach(entry; dirEntries(dir, SpanMode.shallow)) {
                    if(entry.isFile) {
                        auto data = cast(ubyte[])read(entry.name);
                        auto id = baseName(entry.name);
                        nodes[i][id] = data.dup;
                    }
                }
            }
        }
    }

    static size_t hash(string key) {
        size_t h;
        foreach(b; cast(ubyte[])key) {
            h = h * 31 + b;
        }
        return h;
    }

    void store(string id, const(ubyte)[] data) {
        foreach(replica; 0 .. redundancy) {
            auto idx = (hash(id) + replica) % nodes.length;
            nodes[idx][id] = data.dup;
            auto dir = buildPath(basePath, "node" ~ to!string(idx));
            auto file = buildPath(dir, id);
            write(file, data);
        }
    }

    ubyte[] get(string id) const {
        foreach(idx, table; nodes) {
            auto ptr = id in table;
            if(ptr !is null) {
                return (*ptr).dup;
            }
            auto file = buildPath(basePath, "node" ~ to!string(idx), id);
            if (exists(file)) {
                return cast(ubyte[])read(file);
            }
        }
        return null;
    }
}

__gshared Dht gDht;

/// Initialize global DHT instance
void initDht(size_t nodes, size_t redundancy, string path = "dht_data") {
    gDht = Dht(nodes, redundancy, path);
}

/// Store a block in the global DHT
void storeBlock(string id, const(ubyte)[] data) {
    gDht.store(id, data);
}

/// Retrieve a block from the global DHT
ubyte[] getBlock(string id) {
    return gDht.get(id);
}
