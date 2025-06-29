module distributed_fs.fs.node;

import std.stdio;
import std.string;

/// Node type enumeration similar to Plan9
enum NodeType { file, directory };

/// Basic filesystem node
class FsNode {
    string name;
    NodeType type;

    this(string name, NodeType t) {
        this.name = name;
        this.type = t;
    }
}

/// Directory node with children
class DirNode : FsNode {
    FsNode[string] children;

    this(string name) {
        super(name, NodeType.directory);
    }

    void add(FsNode n) {
        children[n.name] = n;
    }

    FsNode opIndex(string child) {
        return child in children ? children[child] : null;
    }
}

/// File node storing metadata for DHT blocks
class FileNode : FsNode {
    string[] blockIds;

    this(string name) {
        super(name, NodeType.file);
    }
}

