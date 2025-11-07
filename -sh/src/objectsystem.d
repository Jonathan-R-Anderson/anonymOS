module objectsystem;

import std.stdio;
import std.string;
import std.conv : to;
import std.array;
import std.algorithm;
import std.file : write, readText, exists;
import md5sum : hexDigest;

struct Object {
    string id;
    string type;
    string[string] props;
    string[] methods;
    string parent;
    string[] children;
    string[][string] acl;
    bool sealed = false;
    bool isolated = false;
}

__gshared Object[string] registry;
__gshared size_t counter;
struct Subscription { string obj; string event; }
__gshared Subscription[size_t] subscriptions;

string createObject(string type) {
    auto id = type ~ "_" ~ to!string(counter++);
    Object obj;
    obj.id = id;
    obj.type = type;
    registry[id] = obj;
    return id;
}

string instantiate(string classPath) {
    if(classPath in registry) {
        auto id = classPath ~ "_" ~ to!string(counter++);
        auto o = registry[classPath];
        o.id = id;
        registry[id] = o;
        return id;
    }
    return createObject(classPath);
}

bool defineClass(string path, string def) {
    auto o = parseSnapshot(def);
    if(o.id.length == 0) o.id = path;
    if(o.type.length == 0) o.type = path;
    registry[path] = o;
    return true;
}

string resolve(string path) {
    return path in registry ? path : "";
}

bool bind(string src, string dst) {
    if(!(src in registry) || (dst in registry)) return false;
    registry[dst] = registry[src];
    registry[dst].id = dst;
    return true;
}

string cloneObj(string obj) {
    if(!(obj in registry)) return "";
    auto id = registry[obj].type ~ "_" ~ to!string(counter++);
    auto o = registry[obj];
    o.id = id;
    registry[id] = o;
    return id;
}

bool deleteObj(string obj) {
    if(obj in registry) { registry.remove(obj); return true; }
    return false;
}

string[] list(string obj) {
    if(obj in registry) return registry[obj].children;
    return [];
}

string introspect(string obj) {
    if(obj !in registry) return "";
    auto o = registry[obj];
    string info = "id="~o.id~";type="~o.type;
    foreach(k,v; o.props) info ~= ";"~k~"="~v;
    return info;
}

static Object parseSnapshot(string snap) {
    Object o;
      foreach(part; snap.split(";")) {
          if(part.length == 0) continue;
          auto kv = part.split("=");
          auto key = kv[0];
          auto val = kv.length > 1 ? kv[1] : "";
        if(key.startsWith("prop:")) {
            auto pkey = key[5 .. $];
            o.props[pkey] = val;
        } else if(key.startsWith("method:")) {
            o.methods ~= val;
        } else switch(key) {
            case "id": o.id = val; break;
            case "type": o.type = val; break;
            case "parent": o.parent = val; break;
            case "children": o.children = val.length ? val.split(",") : []; break;
            case "sealed": o.sealed = val == "1"; break;
            case "isolated": o.isolated = val == "1"; break;
            default: break;
        }
    }
    return o;
}

bool rename(string obj, string newId) {
    if(!(obj in registry) || (newId in registry)) return false;
    auto o = registry[obj];
    registry.remove(obj);
    o.id = newId;
    registry[newId] = o;
    return true;
}

string getType(string obj) {
    if(obj in registry) return registry[obj].type;
    return "";
}

string getProp(string obj, string key) {
    if(obj in registry && key in registry[obj].props)
        return registry[obj].props[key];
    return "";
}

bool setProp(string obj, string key, string val) {
    if(obj !in registry) return false;
    registry[obj].props[key] = val;
    return true;
}

string[] listProps(string obj) {
    if(obj in registry) return registry[obj].props.keys.array;
    return [];
}

bool delProp(string obj, string key) {
    if(obj in registry && key in registry[obj].props) {
        registry[obj].props.remove(key);
        return true;
    }
    return false;
}

string[] listMethods(string obj) {
    if(obj in registry) return registry[obj].methods;
    return [];
}

string callMethod(string obj, string method, string[] args) {
    if(obj !in registry) return "";
    switch(method) {
        case "getProp":
            if(args.length > 0) return getProp(obj, args[0]);
            break;
        case "setProp":
            if(args.length > 1)
                return setProp(obj, args[0], args[1]) ? "true" : "false";
            break;
        case "listProps":
            return listProps(obj).join(",");
        case "listMethods":
            return listMethods(obj).join(",");
        case "getType":
            return getType(obj);
        default:
            break;
    }
    return obj ~ ":" ~ method ~ "(" ~ args.join(",") ~ ")";
}

string describeMethod(string obj, string method) {
    if(obj !in registry) return "";
    return "Method " ~ method ~ " on " ~ obj;
}

string[][string] getACL(string obj) {
    if(obj in registry) return registry[obj].acl;
    return null;
}

bool setACL(string obj, string[][string] acl) {
    if(obj !in registry) return false;
    registry[obj].acl = acl;
    return true;
}

bool grant(string obj, string who, string[] perms) {
    if(obj !in registry) return false;
    registry[obj].acl[who] = perms;
    return true;
}

bool revoke(string obj, string who) {
    if(obj !in registry) return false;
    registry[obj].acl.remove(who);
    return true;
}

string[] capabilities(string obj) {
    if(obj in registry && ("root" in registry[obj].acl))
        return registry[obj].acl["root"];
    return [];
}

size_t subscribe(string obj, string event) {
    static size_t subId;
    subscriptions[subId] = Subscription(obj, event);
    return subId++;
}

bool unsubscribe(size_t id) {
    if(id in subscriptions) { subscriptions.remove(id); return true; }
    return false;
}

bool emit(string obj, string event, string data) {
    bool dispatched;
    foreach(sub; subscriptions.values) {
        if(sub.obj == obj && sub.event == event) {
            dispatched = true;
        }
    }
    return dispatched;
}

bool attach(string parent, string child, string aliasName) {
    if(parent !in registry || child !in registry) return false;
    registry[parent].children ~= aliasName;
    registry[child].parent = parent;
    return true;
}

bool detach(string parent, string name) {
    if(parent !in registry) return false;
    auto idx = registry[parent].children.countUntil(name);
    if(idx == -1) return false;
    registry[parent].children = registry[parent].children[0 .. idx] ~ registry[parent].children[idx+1 .. $];
    return true;
}

string getParent(string obj) {
    if(obj in registry) return registry[obj].parent;
    return "";
}

string[] getChildren(string obj) {
    if(obj in registry) return registry[obj].children;
    return [];
}

bool save(string obj, string path) {
    if(obj !in registry) return false;
    auto data = snapshot(obj);
    write(path, data);
    return true;
}

string load(string path) {
    if(!exists(path)) return "";
    auto data = readText(path);
    auto o = parseSnapshot(data);
    if(o.id.length == 0)
        o.id = o.type ~ "_" ~ to!string(counter++);
    registry[o.id] = o;
    return o.id;
}

string snapshot(string obj) {
    if(obj !in registry) return "";
    auto o = registry[obj];
    string snap = "id=" ~ o.id ~ ";type=" ~ o.type;
    foreach(k,v; o.props) snap ~= ";prop:" ~ k ~ "=" ~ v;
    foreach(m; o.methods) snap ~= ";method:" ~ m;
    if(o.parent.length) snap ~= ";parent=" ~ o.parent;
    if(o.children.length) snap ~= ";children=" ~ o.children.join(",");
    snap ~= ";sealed=" ~ (o.sealed ? "1" : "0");
    snap ~= ";isolated=" ~ (o.isolated ? "1" : "0");
    return snap;
}

bool restore(string obj, string snap) {
    if(obj !in registry) return false;
    auto o = parseSnapshot(snap);
    o.id = obj;
    registry[obj] = o;
    return true;
}

string sandbox(string obj) {
    if(obj in registry) registry[obj].isolated = true;
    return obj;
}

bool isIsolated(string obj) {
    if(obj in registry) return registry[obj].isolated;
    return false;
}

bool seal(string obj) {
    if(obj in registry) { registry[obj].sealed = true; return true; }
    return false;
}

string verify(string obj) {
    if(obj !in registry) return "";
    auto data = cast(const(ubyte)[])snapshot(obj);
    return hexDigest(data);
}

