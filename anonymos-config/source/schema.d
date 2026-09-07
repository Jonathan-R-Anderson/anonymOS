// schema.d — Phase 1 (Stages 1–2) of roadmap/DECLARITIVE_MODEL_ROADMAP.md,
// implementing the schema tree described in roadmap/DECLARATIVE_CONFIG_SPEC.md §2.
//
// The schema is strict at the top level (unknown keys are errors, so a typo is
// caught) but free-form where the kernel already accepts free-form data (the
// objects{} tree, kernel.options{}, gui.themes{}, capabilities{}).  It carries
// richer kind/ref annotations than stock JSON-Schema, which the validator and
// reference-resolver (compiler.d) consume.
//
// This is a HOST tool: plain ldc2 + Phobos (std.json), not the kernel's
// -betterC/-mtriple freestanding flags.  The schema mirrors the kernel's real
// object model so a validated document lowers cleanly onto src/kernel/d/core.
module anonymos.config.schema;

import std.json;
import std.array;
import std.format;

// ── Schema node ──────────────────────────────────────────────────────────────
// A node is one of the SchemaKind variants.  `props` applies to objects,
// `items` to arrays, `enumVals` to enums, and `refKind` annotates a string as a
// cross-section reference the compiler resolves in Stage 4.
enum SchemaKind
{
    objectK,
    arrayK,
    stringK,
    enumK,
    intK,
    boolK,
    colorK,   // "#RRGGBB" or "#AARRGGBB"
    refK,     // string naming an entity in another section
    freeK,    // free-form: accept any JSON value (objects{}, kernel.options{})
}

enum RefKind
{
    none,
    identity,    // names an identities[].name
    namespace,   // names a namespaces[].name
    service,     // names a services[].name
    ipc,         // names an ipc[].name
    storage,     // names a storage[].name
    snapshot,    // names a snapshots[].name
    capability,  // names a capabilities{} key
    object,      // a $name object reference into objects{}
}

enum LiveClass { live, reboot }

struct SchemaNode
{
    SchemaKind kind;
    string description;
    bool required;            // for a property: must be present
    bool allowUnknownKeys;    // for objectK: accept props not in `props`
    RefKind refKind;          // for refK/stringK
    SchemaNode[string] props; // for objectK
    SchemaNode* items;        // for arrayK (pointer: SchemaNode can't hold itself by value)
    string[] enumVals;        // for enumK
    LiveClass liveClass;      // §13 hint emitted into the compiled manifest
}

// Build the property map (owned by the caller).  Returns a fresh node by value.
SchemaNode node(SchemaKind k) { SchemaNode n; n.kind = k; return n; }

SchemaNode obj(SchemaNode[string] props, bool required = false, bool allowUnknown = false)
{
    auto n = node(SchemaKind.objectK);
    n.props = props;
    n.required = required;
    n.allowUnknownKeys = allowUnknown;
    return n;
}

SchemaNode arr(SchemaNode item, bool required = false)
{
    auto n = node(SchemaKind.arrayK);
    // Heap-allocate the items node (SchemaNode cannot hold itself by value);
    // copy-assign via an explicit slot.
    auto slot = new SchemaNode;
    *slot = item;
    n.items = slot;
    n.required = required;
    return n;
}

SchemaNode str(bool required = false, RefKind rk = RefKind.none, LiveClass lc = LiveClass.reboot)
{
    auto n = node(SchemaKind.stringK);
    n.required = required;
    n.refKind = rk;
    n.liveClass = lc;
    return n;
}

// live-reconfiguring string (§13): GUI color, hostname, logging sink, …
SchemaNode strLive(RefKind rk = RefKind.none) { return str(false, rk, LiveClass.live); }

SchemaNode enumN(string[] vals, bool required = false, LiveClass lc = LiveClass.reboot)
{
    auto n = node(SchemaKind.enumK);
    n.enumVals = vals;
    n.required = required;
    n.liveClass = lc;
    return n;
}

// live-reconfiguring enum (logging level, gui border policy).
SchemaNode enumLive(string[] vals) { return enumN(vals, false, LiveClass.live); }

SchemaNode colorNode(bool required = false)
{
    auto n = node(SchemaKind.colorK);
    n.required = required;
    n.liveClass = LiveClass.live; // GUI color changes are live (§13)
    return n;
}

SchemaNode freeNode(bool required = false, LiveClass lc = LiveClass.reboot)
{
    auto n = node(SchemaKind.freeK);
    n.required = required;
    n.liveClass = lc;
    return n;
}

SchemaNode freeLive() { return freeNode(false, LiveClass.live); }

SchemaNode intN(bool required = false, LiveClass lc = LiveClass.reboot)
{
    auto n = node(SchemaKind.intK);
    n.required = required;
    n.liveClass = lc;
    return n;
}

SchemaNode boolN(bool required = false, LiveClass lc = LiveClass.live)
{
    auto n = node(SchemaKind.boolK);
    n.required = required;
    n.liveClass = lc;
    return n;
}

// reboot-class boolean (boot.measured, compatibility.enabled, …).
SchemaNode boolReboot(bool required = false) { return boolN(required, LiveClass.reboot); }
// live-class boolean (security/audit toggles, networking dhcp).
SchemaNode boolLive(bool required = false) { return boolN(required, LiveClass.live); }
SchemaNode strReboot(RefKind rk = RefKind.none) { return str(false, rk, LiveClass.reboot); }
SchemaNode intReboot() { return intN(false, LiveClass.reboot); }
SchemaNode freeReboot() { return freeNode(false, LiveClass.reboot); }

// ── The top-level document schema (spec §2.1) ────────────────────────────────
// Returns the root object node whose props are the 18 top-level keys (17 named
// sections + the `imports` consumed by the module system, §11).
SchemaNode documentSchema()
{
    SchemaNode[string] top;

    // system (§2): machine identity + generation linkage
    {
        SchemaNode[string] p;
        p["name"] = str();
        p["hostname"] = strLive();
        p["generation"] = intReboot();
        top["system"] = obj(p);
    }
    // kernel (§2): enabled features + boot options
    {
        SchemaNode[string] p;
        p["features"] = arr(str());
        p["options"] = freeReboot();
        top["kernel"] = obj(p);
    }
    // boot (§4): trusted-config discovery + verification
    {
        SchemaNode[string] p;
        p["configPath"] = strReboot();
        p["measured"] = boolReboot();
        p["signature"] = strReboot();
        top["boot"] = obj(p);
    }
    // objects (§5): free-form name→node tree
    {
        SchemaNode[string] p;
        p["_type"] = str();
        p["source"] = str();
        p["writable"] = boolN();
        top["objects"] = obj(null, false, true); // free-form map of named objects
    }
    // identities (§7): Qubes-style domains
    {
        SchemaNode[string] p;
        p["name"] = str(true);
        p["color"] = colorNode();
        p["trust"] = enumN(["system", "banking", "work", "personal", "dev", "untrusted", "disposable"]);
        p["rightsCeiling"] = str(true, RefKind.capability);
        p["namespace"] = str(false, RefKind.namespace);
        p["net"] = enumN(["none", "nat", "vpn", "tor", "localonly", "disposable"]);
        p["clip"] = enumN(["deny", "ask", "same", "down"]);
        p["gui"] = arr(enumN(["borderAlways", "titleLabel", "noScreenshotAcrossId", "noGlobalGrab"]));
        p["devices"] = arr(str());
        p["disposable"] = boolN();
        p["template"] = str(false, RefKind.identity);
        top["identities"] = arr(obj(p));
    }
    // domains (DOMAIN_MANAGER §2): reusable OS-environment objects referencing an identity.
    // DM1 validates + compiles the core fields (name/type/identity/template/persist); the richer
    // fields are accepted free-form now and gain explicit schemas + compilation in later milestones
    // (filesystemAccess → DM2, packages → DM7, …).
    {
        SchemaNode[string] p;
        p["name"] = str(true);
        p["type"] = enumN(["domain", "template"]);
        p["identity"] = str(false, RefKind.identity);   // the security identity this domain binds to
        p["template"] = str();                          // DM6: the referenced template's name (a domains[] entry)
        p["persist"] = enumN(["ephemeral", "home-only", "full"]);
        p["packages"] = arr(str());
        p["applications"] = arr(str());
        p["services"] = arr(str(false, RefKind.service));
        p["startupPrograms"] = arr(str());
        p["environment"] = freeNode();
        p["defaults"] = freeNode();
        // DM2.3: the restricted-filesystem policy — the core fields are validated + compiled;
        // mounts/sharedFolders/tempFolders/packageWritable/execPaths/allowCrossDomainAccess are
        // accepted (allowUnknown) but compiled in later milestones.
        {
            SchemaNode[string] fp;
            fp["defaultPolicy"] = enumN(["deny", "allow"]);
            fp["readOnly"]  = arr(str());
            fp["readWrite"] = arr(str());
            fp["deny"]      = arr(str());
            fp["allowTraversalOutsideMounts"] = boolN();
            fp["homeVisible"] = boolN();
            p["filesystemAccess"] = obj(fp, false, true);
        }
        p["networkPolicy"] = freeNode();
        p["permissions"] = freeNode();
        p["appearance"] = freeNode();
        p["policies"] = freeNode();
        p["linux"] = freeNode();
        top["domains"] = arr(obj(p));
    }
    // namespaces (§5/§7): object-tree roots
    {
        SchemaNode[string] p;
        p["name"] = str(true);
        p["root"] = str(false, RefKind.object);
        p["inherits"] = str(false, RefKind.namespace);
        p["isolated"] = boolN();
        {
            SchemaNode[string] mp;
            mp["path"] = str();
            mp["target"] = str(false, RefKind.object);
            mp["rights"] = str();
            p["mounts"] = arr(obj(mp));
        }
        top["namespaces"] = arr(obj(p));
    }
    // services (§6): object-native services
    {
        SchemaNode[string] p;
        p["name"] = str(true);
        p["executable"] = str();
        p["identity"] = str(false, RefKind.identity);
        p["namespace"] = str(false, RefKind.namespace);
        p["capabilities"] = arr(str(false, RefKind.capability));
        p["depends"] = arr(str(false, RefKind.service));
        p["after"] = arr(str(false, RefKind.service));
        p["restart"] = enumN(["always", "on-failure", "never"], false, LiveClass.live);
        p["ipc"] = str(false, RefKind.ipc);
        p["mounts"] = arr(str(false, RefKind.storage));
        top["services"] = arr(obj(p));
    }
    // processes (§6): one-shot tasks
    {
        SchemaNode[string] p;
        p["name"] = str(true);
        p["executable"] = str();
        p["identity"] = str(false, RefKind.identity);
        p["capabilities"] = arr(str(false, RefKind.capability));
        p["after"] = arr(str(false, RefKind.service));
        top["processes"] = arr(obj(p));
    }
    // capabilities (§8): named capability lattice — free-form name→cap map
    // (allowUnknownKeys so the per-cap names like fs-ro/admin are accepted).
    {
        SchemaNode[string] cp;
        cp["rights"] = arr(str());          // right names or "all"
        cp["inherits"] = str(false, RefKind.capability);
        top["capabilities"] = obj(cp, false, true);
    }
    // ipc (§9): secure-IPC policy + audit
    {
        SchemaNode[string] p;
        p["name"] = str(true);
        p["dh"] = boolN();
        p["keyBroker"] = str(false, RefKind.service);
        p["audit"] = boolN();
        SchemaNode[string] allow;
        allow["from"] = str(true, RefKind.identity);
        allow["to"] = str(true, RefKind.identity);
        allow["broker"] = str(false, RefKind.service);
        p["allow"] = arr(obj(allow));
        top["ipc"] = arr(obj(p));
    }
    // storage (§5): object-store / fs mounts
    {
        SchemaNode[string] p;
        p["name"] = str(true);
        p["kind"] = enumN(["immutable", "object-store"], true);
        p["generation"] = str(false, RefKind.snapshot);
        p["source"] = str();
        p["readOnly"] = boolN();
        top["storage"] = arr(obj(p));
    }
    // networking (§2)
    {
        SchemaNode[string] p;
        p["hostname"] = strLive();
        p["dns"] = arr(str());
        SchemaNode[string] iface;
        iface["name"] = str();
        iface["dhcp"] = boolN();
        p["interfaces"] = arr(obj(iface));
        top["networking"] = obj(p);
    }
    // gui (§2/§9 topic): GUI / window identity colors
    {
        SchemaNode[string] p;
        p["compositor"] = strReboot();
        p["borderPolicy"] = enumN(["always", "trusted-only", "never"], false, LiveClass.live);
        p["defaultColor"] = colorNode();
        p["themes"] = freeLive();
        top["gui"] = obj(p);
    }
    // compatibility (§2): Linux + Windows/ReactOS layers.  Each layer
    // (linux, windows, …) is a free-form sub-object of per-layer settings
    // (enabled, personality, backend, …).
    {
        top["compatibility"] = obj(null, false, true);
    }
    // security (§2): profiles + immutable-image
    {
        SchemaNode[string] p;
        p["rootless"] = boolN();
        p["immutableImage"] = boolReboot();
        p["profiles"] = arr(strLive());
        top["security"] = obj(p);
    }
    // logging (§2): logging / auditing
    {
        SchemaNode[string] p;
        p["level"] = enumN(["error", "warn", "info", "debug"], false, LiveClass.live);
        p["audit"] = boolLive();
        p["sink"] = strLive();
        top["logging"] = obj(p);
    }
    // snapshots (§10): rollback generations
    {
        SchemaNode[string] p;
        p["name"] = str(true);
        p["base"] = str(false, RefKind.snapshot);
        p["auto"] = boolN();
        top["snapshots"] = arr(obj(p));
    }
    // distributed (§2): distributed-OS features
    {
        SchemaNode[string] p;
        p["enabled"] = boolReboot();
        p["cluster"] = arr(strReboot());
        top["distributed"] = obj(p);
    }
    // imports (§11): module files (consumed and removed after merge)
    top["imports"] = arr(str());

    auto root = obj(top, true, false); // top level itself is required-object
    return root;
}

// ── export_json_schema: emit a stock JSON-Schema doc for editor autocomplete ──
// (spec Phase 1 deliverable: "schema data + export_json_schema".)
JSONValue exportJsonSchema()
{
    // Single recursive emitter (self-referential nested functions need a
    // forward declaration in D; emitted once, defined once below).
    void emitNode(ref JSONValue out_, const ref SchemaNode n)
    {
        auto o = JSONValue(string[string].init);
        final switch (n.kind)
        {
        case SchemaKind.objectK:
            o.object["type"] = "object";
            JSONValue props = JSONValue(string[string].init);
            foreach (k, child; n.props)
            {
                JSONValue c;
                emitNode(c, child);
                props.object[k] = c;
            }
            o.object["properties"] = props;
            if (!n.allowUnknownKeys)
                o.object["additionalProperties"] = JSONValue(false);
            JSONValue reqs = JSONValue(string[].init);
            foreach (k, child; n.props)
                if (child.required) reqs.array ~= JSONValue(k);
            if (reqs.array.length) o.object["required"] = reqs;
            break;
        case SchemaKind.arrayK:
            o.object["type"] = "array";
            JSONValue it = JSONValue(string[string].init);
            if (n.items) emitNode(it, *n.items);
            o.object["items"] = it;
            break;
        case SchemaKind.stringK:
        case SchemaKind.colorK:
        case SchemaKind.refK:
            o.object["type"] = "string";
            if (n.refKind != RefKind.none)
                o.object["x-ref"] = format("%s", n.refKind);
            break;
        case SchemaKind.enumK:
            o.object["type"] = "string";
            JSONValue ev = JSONValue(string[].init);
            foreach (v; n.enumVals) ev.array ~= JSONValue(v);
            o.object["enum"] = ev;
            break;
        case SchemaKind.intK:
            o.object["type"] = "integer";
            break;
        case SchemaKind.boolK:
            o.object["type"] = "boolean";
            break;
        case SchemaKind.freeK:
            break; // accept anything
        }
        if (n.description.length) o.object["description"] = JSONValue(n.description);
        out_ = o;
    }

    auto root = documentSchema();
    auto doc = JSONValue(string[string].init);
    doc.object["$schema"] = JSONValue("https://json-schema.org/draft/2020-12/schema");
    doc.object["$id"] = JSONValue("https://anonymos.org/system.schema.json");
    doc.object["title"] = JSONValue("anonymOS declarative system configuration");
    doc.object["type"] = JSONValue("object");
    JSONValue props = JSONValue(string[string].init);
    foreach (k, child; root.props)
    {
        JSONValue c;
        emitNode(c, child);
        props.object[k] = c;
    }
    doc.object["properties"] = props;
    doc.object["additionalProperties"] = JSONValue(false);
    return doc;
}
