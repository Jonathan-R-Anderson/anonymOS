module distributed_fs.objectfs;

import distributed_fs.fs.node;
import distributed_fs.fs.storage : writeFile;
import distributed_fs.objecttree;
import std.string : join;
import std.conv : to;

/// Build a filesystem tree from an object namespace
class ObjectFS {
    DirNode root;

    this(ObjNode* objRoot) {
        root = new DirNode("/");
        build(objRoot, root);
    }

    private void build(ObjNode* obj, DirNode parent) {
        if(obj is null) return;
        DirNode dir = parent;
        if(obj.name != "/") {
            dir = new DirNode(obj.name);
            parent.add(dir);
        }
        if(obj.methods.length) {
            auto f = new FileNode("methods.txt");
            dir.add(f);
            auto data = join(obj.methods, "\n");
            writeFile(f, cast(ubyte[])data);
        }
        if(obj.props.length) {
            auto f = new FileNode("props.txt");
            dir.add(f);
            string[] lines;
            foreach(p; obj.props) {
                lines ~= p.name ~ "=" ~ to!string(p.value);
            }
            writeFile(f, cast(ubyte[])join(lines, "\n"));
        }
        ObjNode* child = obj.child;
        while(child !is null) {
            build(child, dir);
            child = child.sibling;
        }
    }
}

