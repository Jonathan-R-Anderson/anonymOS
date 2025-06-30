module kernel.object_namespace;

pragma(LDC_no_moduleinfo);

import kernel.lib.stdc.stdlib : malloc, realloc, free;
import kernel.types : strlen, memcpy, memcmp;
import kernel.process_manager : obj_pm_create_process, obj_pm_run;
import kernel.user_manager : obj_um_create_user, obj_um_set_current_user, obj_um_get_current_user;
import kernel.object_validator : validate_object_graph;

public:

alias ObjMethodFunc = extern(C) long function(Object*, void**, size_t);

struct ObjMethod {
    const(char)* name;
    ObjMethodFunc func;
}

struct ObjProperty {
    const(char)* name;
    long value;
}

struct Object {
    const(char)* name;
    Object* parent;
    Object* child;
    Object* sibling;
    ObjMethod* methods;
    size_t methodCount;
    size_t methodCapacity;
    ObjProperty* properties;
    size_t propCount;
    size_t propCapacity;
}

private void free_object_recursive(Object* obj)
{
    if(obj is null) return;
    auto child = obj.child;
    while(child !is null)
    {
        auto next = child.sibling;
        free_object_recursive(child);
        child = next;
    }
    if(obj.methods !is null) free(obj.methods);
    if(obj.properties !is null) free(obj.properties);
    free(obj);
}

__gshared Object* rootObject;

private bool str_eq(const(char)* a, const(char)* b)
{
    if(a is null || b is null) return false;
    auto la = strlen(a);
    auto lb = strlen(b);
    if(la != lb) return false;
    return memcmp(a, b, la) == 0;
}

extern(C) Object* obj_create(const(char)* name)
{
    auto obj = cast(Object*)malloc(Object.sizeof);
    if(obj is null) return null;
    obj.name = name;
    obj.parent = null;
    obj.child = null;
    obj.sibling = null;
    obj.methods = null;
    obj.methodCount = 0;
    obj.methodCapacity = 0;
    obj.properties = null;
    obj.propCount = 0;
    obj.propCapacity = 0;
    return obj;
}

extern(C) void obj_add_child(Object* parent, Object* child)
{
    if(parent is null || child is null) return;
    child.parent = parent;
    child.sibling = parent.child;
    parent.child = child;
}

private void unlink_child(Object* parent, Object* child)
{
    if(parent is null || child is null) return;
    if(parent.child is child)
    {
        parent.child = child.sibling;
        return;
    }
    auto c = parent.child;
    while(c !is null && c.sibling !is child)
        c = c.sibling;
    if(c !is null)
        c.sibling = child.sibling;
}

extern(C) void obj_remove(Object* obj)
{
    if(obj is null || obj is rootObject) return;
    unlink_child(obj.parent, obj);
    free_object_recursive(obj);
}

extern(C) int obj_add_method(Object* obj, const(char)* name, ObjMethodFunc func)
{
    if(obj is null) return -1;
    if(obj.methodCount == obj.methodCapacity)
    {
        size_t newCap = obj.methodCapacity ? obj.methodCapacity * 2 : 4;
        auto newMem = cast(ObjMethod*)realloc(obj.methods, newCap * ObjMethod.sizeof);
        if(newMem is null) return -1;
        obj.methods = newMem;
        obj.methodCapacity = newCap;
    }
    obj.methods[obj.methodCount].name = name;
    obj.methods[obj.methodCount].func = func;
    obj.methodCount++;
    return 0;
}

extern(C) int obj_set_property(Object* obj, const(char)* name, long value)
{
    if(obj is null) return -1;
    foreach(i; 0 .. obj.propCount)
    {
        if(str_eq(obj.properties[i].name, name))
        {
            obj.properties[i].value = value;
            return 0;
        }
    }
    if(obj.propCount == obj.propCapacity)
    {
        size_t newCap = obj.propCapacity ? obj.propCapacity * 2 : 4;
        auto newMem = cast(ObjProperty*)realloc(obj.properties, newCap * ObjProperty.sizeof);
        if(newMem is null) return -1;
        obj.properties = newMem;
        obj.propCapacity = newCap;
    }
    obj.properties[obj.propCount].name = name;
    obj.properties[obj.propCount].value = value;
    obj.propCount++;
    return 0;
}

private Object* find_child(Object* parent, const(char)* name)
{
    auto c = parent.child;
    while(c !is null)
    {
        if(str_eq(c.name, name))
            return c;
        c = c.sibling;
    }
    return null;
}

extern(C) Object* obj_lookup(const(char)* path)
{
    if(path is null || path[0] != '/') return null;
    auto cur = rootObject;
    size_t i = 1;
    char[64] nameBuf;
    while(cur !is null && path[i] != 0)
    {
        size_t j = 0;
        while(path[i] != '/' && path[i] != 0 && j < nameBuf.length-1)
            nameBuf[j++] = path[i++];
        nameBuf[j] = 0;
        if(j == 0)
        {
            if(path[i] == '/') i++;
            continue;
        }
        cur = find_child(cur, nameBuf.ptr);
        if(cur is null) return null;
        if(path[i] == '/') i++;
    }
    return cur;
}

private Object* ensure_path(const(char)* path, bool createMissing)
{
    if(path is null || path[0] != '/') return null;
    auto cur = rootObject;
    size_t i = 1;
    char[64] nameBuf;
    while(cur !is null && path[i] != 0)
    {
        size_t j = 0;
        while(path[i] != '/' && path[i] != 0 && j < nameBuf.length-1)
            nameBuf[j++] = path[i++];
        nameBuf[j] = 0;
        if(j == 0)
        {
            if(path[i] == '/') i++;
            continue;
        }
        auto next = find_child(cur, nameBuf.ptr);
        if(next is null)
        {
            if(!createMissing) return null;
            next = obj_create(nameBuf.ptr);
            obj_add_child(cur, next);
        }
        cur = next;
        if(path[i] == '/') i++;
    }
    return cur;
}

extern(C) Object* obj_create_path(const(char)* path)
{
    return ensure_path(path, true);
}

extern(C) int obj_destroy_path(const(char)* path)
{
    auto obj = ensure_path(path, false);
    if(obj is null || obj is rootObject) return -1;
    obj_remove(obj);
    return 0;
}

extern(C) long obj_call(const(char)* path, const(char)* methodName, void** args, size_t nargs)
{
    auto obj = obj_lookup(path);
    if(obj is null) return -1;
    foreach(i; 0 .. obj.methodCount)
    {
        if(str_eq(obj.methods[i].name, methodName))
            return obj.methods[i].func(obj, args, nargs);
    }
    return -1;
}

extern(C) void object_namespace_init()
{
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
    obj_add_method(scheduler, "create", &obj_pm_create_process);
    obj_add_method(scheduler, "run", &obj_pm_run);

    auto userMgr = obj_create("userManager");
    obj_add_child(user, userMgr);
    obj_add_method(userMgr, "createUser", &obj_um_create_user);
    obj_add_method(userMgr, "setCurrentUser", &obj_um_set_current_user);
    obj_add_method(userMgr, "getCurrentUser", &obj_um_get_current_user);

    // Validate the object graph using A* search
    validate_object_graph();
}

