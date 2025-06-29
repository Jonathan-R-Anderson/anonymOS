module distributed_fs.storage;

public import distributed_fs.storage.dht;
public import distributed_fs.storage.local;

enum StoreMode { Dht, Local }
__gshared StoreMode storeMode;

void initDhtStore(size_t nodes, size_t redundancy, string path = "dht_data") {
    initDht(nodes, redundancy, path);
    storeMode = StoreMode.Dht;
}

void initLocalStore(string path = "fs_data") {
    initLocal(path);
    storeMode = StoreMode.Local;
}

/// Store a block using the selected backend.
void storeBlockWrapper(string id, const(ubyte)[] data) {
    final switch(storeMode) {
        case StoreMode.Dht: storeBlock(id, data); break;
        case StoreMode.Local: storeLocal(id, data); break;
    }
}

/// Retrieve a block using the selected backend.
ubyte[] getBlockWrapper(string id) {
    final switch(storeMode) {
        case StoreMode.Dht: return getBlock(id);
        case StoreMode.Local: return getLocal(id);
    }
    return null;
}
