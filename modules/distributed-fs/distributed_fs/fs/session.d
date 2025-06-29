module distributed_fs.fs.session;

import distributed_fs.fs.plan9;
import distributed_fs.fs.node : DirNode;

/// Filesystem namespace for a single process session.
class SessionFS {
    Plan9FS fs;

    this(SessionFS parent = null, DirNode srvMount = null) {
        if(parent is null)
            fs = new Plan9FS(srvMount);
        else
            fs = parent.fs; // share parent's namespace
    }

    DirNode rootDir() {
        return fs.rootDir();
    }
}

