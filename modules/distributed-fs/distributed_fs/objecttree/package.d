module distributed_fs.objecttree;

import std.string : split, join;

struct Property {
    string name;
    long value;
}

struct ObjNode {
    string name;
    ObjNode* parent;
    ObjNode* child;
    ObjNode* sibling;
    string[] methods;
    Property[] props;
}

ObjNode* obj_create(string name) {
    auto obj = new ObjNode;
    obj.name = name;
    return obj;
}

void obj_add_child(ObjNode* parent, ObjNode* child) {
    if(parent is null || child is null) return;
    child.parent = parent;
    child.sibling = parent.child;
    parent.child = child;
}

ObjNode* obj_lookup(ObjNode* root, string path) {
    if(path.length == 0 || path[0] != '/') return null;
    auto cur = root;
    foreach(part; path[1..$].split('/')) {
        if(part.length == 0) continue;
        ObjNode* c = cur.child;
        while(c !is null && c.name != part)
            c = c.sibling;
        if(c is null) return null;
        cur = c;
    }
    return cur;
}

ObjNode* rootObject;

void object_namespace_init() {
    rootObject = obj_create("/");
    auto sys = obj_create("sys");
    auto net = obj_create("net");
    auto user = obj_create("user");
    auto dev = obj_create("dev");
    auto proc = obj_create("proc");
    auto srv = obj_create("srv");
    obj_add_child(rootObject, sys);
    obj_add_child(rootObject, net);
    obj_add_child(rootObject, user);
    obj_add_child(rootObject, dev);
    obj_add_child(rootObject, proc);
    obj_add_child(rootObject, srv);

    auto scheduler = obj_create("scheduler");
    obj_add_child(sys, scheduler);
    scheduler.methods ~= ["create", "run"];

    auto userMgr = obj_create("userManager");
    obj_add_child(user, userMgr);
    userMgr.methods ~= ["createUser", "setCurrentUser", "getCurrentUser"];
}

