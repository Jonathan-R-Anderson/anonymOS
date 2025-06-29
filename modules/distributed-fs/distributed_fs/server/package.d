module distributed_fs.server;

import std.stdio;
import distributed_fs.fs;
import distributed_fs.storage;
import distributed_fs.objecttree;
import distributed_fs.objectfs;

SessionFS rootSession;

/// Start the filesystem server. When `useDht` is false, data is stored only on disk.
void startServer(bool useDht = true) {
    writeln("starting server");
    if(useDht)
        initDhtStore(4, 2); // 4 nodes with 2-way redundancy
    else
        initLocalStore();

    // initialize object namespace and derive filesystem from it
    object_namespace_init();
    auto ofs = new ObjectFS(rootObject);
    rootSession = new SessionFS(null, ofs.root);
}

