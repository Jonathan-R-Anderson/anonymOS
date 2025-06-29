module distributed_fs.fs.plan9;

import distributed_fs.fs.node;

/// Plan9-like filesystem tree
class Plan9FS {
    DirNode root;
    DirNode home;

    this(DirNode srvMount = null) {
        root = new DirNode("/");
        root.add(new DirNode("bin"));
        root.add(new DirNode("etc"));
        root.add(new DirNode("usr"));
        root.add(new DirNode("lib"));
        root.add(new DirNode("sbin"));
        root.add(new DirNode("var"));
        root.add(new DirNode("tmp"));
        root.add(new DirNode("dev"));
        root.add(new DirNode("proc"));
        home = new DirNode("home");
        root.add(home);
        auto srv = new DirNode("srv");
        if(srvMount !is null)
            srv.add(srvMount);
        root.add(srv);
    }

    /// create user directory with session customizations
    DirNode createUser(string name) {
        auto udir = new DirNode(name);
        udir.add(new DirNode("env"));
        udir.add(new DirNode("sessions"));
        home.add(udir);
        return udir;
    }

    /// expose root directory
    DirNode rootDir() {
        return root;
    }
}

