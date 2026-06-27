// compiler.d — Phases 2–4, 5–9, 11–12 of the declarative-config compiler.
// Lowers one resolved JSON document (after imports, validator.d Stage 3) into a
// CompiledGraph: the boot plan, service graph + topological startup order, the
// capability manifest, the materialized IPC rules, identity/namespace tables,
// and the per-section live-vs-reboot classification.
//
// Stages implemented here (DECLARATIVE_CONFIG_SPEC.md §3):
//   Stage 4 — resolve references (every ref/$name target exists)
//   Stage 5 — assign stable object IDs (deterministic order)
//   Stage 6 — detect cycles (3-color DFS over 4 edge sets)
//   Stage 7 — check capabilities (subset narrowing; service ⊆ ceiling)
//   Stage 8 — lower to CompiledGraph (service graph, boot plan, ipc, tables)
module anonymos.config.compiler;

import anonymos.config.schema;
import anonymos.config.caplattice;
import std.json;
import std.array;
import std.algorithm;
import std.format;
import std.conv;

// ── Compiler problem (Stages 4/6/7 semantic errors, with exact paths) ─────────
struct CompileError
{
    string path;   // e.g. "services[2].depends[0]"
    string message;
    string toString() const { return format("%s: %s", path, message); }
}

// ── Stage 5: the object graph node (spec §3 data structures) ─────────────────
enum ObjKind
{
    system,
    object,
    namespace,
    identity,
    service,
    process,
    ipc,
    storage,
    snapshot,
    capability,
}

// Map a config object kind → the kernel ObjType name (spec Appendix A).
string objKindToType(ObjKind k)
{
    final switch (k)
    {
    case ObjKind.system:     return "Directory"; // system root dir context
    case ObjKind.object:     return "(declared _type)";
    case ObjKind.namespace:  return "Namespace";
    case ObjKind.identity:   return "Identity";
    case ObjKind.service:    return "Service";
    case ObjKind.process:    return "Process";
    case ObjKind.ipc:        return "Endpoint";
    case ObjKind.storage:    return "File";
    case ObjKind.snapshot:   return "Generation";
    case ObjKind.capability: return "Capability";
    }
}

struct ObjectNode
{
    uint id;        // dense, deterministic logical id
    ObjKind kind;
    string name;    // section-local name (or objects{} key)
    string objType; // kernel ObjType name
    string section; // source section
    uint index;     // index within its array section
    JSONValue payload;
    string source;  // human path like "services[2]"
}

// ── Stage 8 outputs: the compiled graph ───────────────────────────────────────
struct CapEntry { string name; uint mask; string parent; string[] bits; }

struct IpcRule
{
    string policy;   // ipc[].name
    string fromId;
    string toId;
    string broker;   // service name or ""
    bool dh;
    bool audit;
}

struct IdentityRecFields
{
    string name;
    uint color;       // packed 0xAARRGGBB
    string trust;
    string rightsCeiling;
    string namespace_;
    string net;
    string clip;
    string[] gui;
    string[] devices;
    bool disposable;
    string template_;
}

struct NamespaceRecFields
{
    string name;
    string root;       // object name or ""
    string inherits;   // parent namespace name or ""
    bool isolated;
}

// DOMAIN_MANAGER DM1: a domain references an identity (security domain) + optionally a
// template; the richer manifest fields are validated/accepted but compiled in later milestones.
struct DomainRecFields
{
    string name;
    string type_;       // "domain" | "template" (default "domain")
    string identity;    // the identity name this domain binds to ("" → same-named identity)
    string template_;   // parent template name (DM6); "" = none
    string persist;     // "ephemeral" | "home-only" | "full" (default "ephemeral")
}

struct BootStep
{
    string phase; // "trusted" | "object-tree" | "services"
    string kind;  // e.g. "select-generation", "identityCreate", "serviceStartAll"
    string target; // object name / service
    string note;
}

struct CompiledGraph
{
    ObjectNode[] objects;
    string[string] serviceGraph;        // service name → "dep,dep" (depends∪after)
    string[] startupOrder;              // topological, declaration-order tie-break
    BootStep[] bootPlan;
    CapEntry[string] capabilityManifest;
    IpcRule[] ipcRules;
    IdentityRecFields[string] identityTable;
    DomainRecFields[string] domainTable;          // DOMAIN_MANAGER DM1
    NamespaceRecFields[string] namespaceTable;
    string configHash;                  // sha256(canonical_json)[:16] — set by caller
    LiveClass[string] liveReconfig;     // section → live/reboot
    string[] warnings;
    string[] errors;                    // populated only if compile() returns false
}

// ── Public entry: run the full Stage 1–8 chain on a resolved document ─────────
// Returns true and fills `g` on success; on failure returns false with g.errors
// populated (collect-all).  `configHash` is computed by the caller (generations.d)
// and stitched in, but a stable hash is also derivable here.
bool compile(const ref JSONValue doc, ref CompiledGraph g, ref CompileError[] errors)
{
    g = CompiledGraph.init;

    // Build section name tables (for reference resolution, Stage 4).
    auto tables = buildNameTables(doc);

    // Stage 4: resolve references.
    resolveReferences(doc, tables, errors);

    // Stage 5: assign stable object IDs.
    g.objects = assignIds(doc);

    // Stage 6: detect cycles over four edge sets.
    detectCycles(doc, errors);

    // Stage 7: check capabilities (subset + ceiling).
    checkCapabilities(doc, tables, g.capabilityManifest, errors);

    // Phase 4: service graph + topological startup order.
    g.serviceGraph = buildServiceGraph(doc);
    string[] topoErrs;
    g.startupOrder = topologicalOrder(doc, topoErrs);
    foreach (e; topoErrs)
    {
        CompileError ce; ce.path = "services"; ce.message = e; errors ~= ce;
    }

    // Phase 5/7/9: materialize tables + ipc rules.
    g.identityTable = buildIdentityTable(doc);
    g.domainTable = buildDomainTable(doc);        // DOMAIN_MANAGER DM1
    g.namespaceTable = buildNamespaceTable(doc);
    g.ipcRules = buildIpcRules(doc, tables, errors);

    // Boot plan + live classification + warnings.
    g.bootPlan = buildBootPlan(doc, g.startupOrder);
    g.liveReconfig = classifyLive(doc);
    emitWarnings(doc, g.warnings);

    return errors.length == 0;
}

// ── Name tables ───────────────────────────────────────────────────────────────
struct NameTables
{
    string[string] identities;
    string[string] namespaces;
    string[string] services;
    string[string] ipc;
    string[string] storage;
    string[string] snapshots;
    string[string] capabilities;
    string[string] objects;
    string[string] processes;
}

NameTables buildNameTables(const ref JSONValue doc)
{
    NameTables t;
    if (doc.type != JSONType.object) return t;
    if (auto a = "identities" in doc.object)
        foreach (i, e; a.array) if (e.type == JSONType.object)
            if (auto n = "name" in e.object) t.identities[n.str] = n.str;
    if (auto a = "namespaces" in doc.object)
        foreach (i, e; a.array) if (e.type == JSONType.object)
            if (auto n = "name" in e.object) t.namespaces[n.str] = n.str;
    if (auto a = "services" in doc.object)
        foreach (i, e; a.array) if (e.type == JSONType.object)
            if (auto n = "name" in e.object) t.services[n.str] = n.str;
    if (auto a = "processes" in doc.object)
        foreach (i, e; a.array) if (e.type == JSONType.object)
            if (auto n = "name" in e.object) t.processes[n.str] = n.str;
    if (auto a = "ipc" in doc.object)
        foreach (i, e; a.array) if (e.type == JSONType.object)
            if (auto n = "name" in e.object) t.ipc[n.str] = n.str;
    if (auto a = "storage" in doc.object)
        foreach (i, e; a.array) if (e.type == JSONType.object)
            if (auto n = "name" in e.object) t.storage[n.str] = n.str;
    if (auto a = "snapshots" in doc.object)
        foreach (i, e; a.array) if (e.type == JSONType.object)
            if (auto n = "name" in e.object) t.snapshots[n.str] = n.str;
    if (auto o = "capabilities" in doc.object)
        if (o.type == JSONType.object)
            foreach (k, _; o.object) t.capabilities[k] = k;
    if (auto o = "objects" in doc.object)
        if (o.type == JSONType.object)
            foreach (k, _; o.object) t.objects[k] = k;
    return t;
}

bool nameExists(const ref NameTables t, RefKind rk, string name)
{
    final switch (rk)
    {
    case RefKind.none:        return true;
    case RefKind.identity:    return (name in t.identities) !is null;
    case RefKind.namespace:   return (name in t.namespaces) !is null;
    case RefKind.service:     return (name in t.services) !is null;
    case RefKind.ipc:         return (name in t.ipc) !is null;
    case RefKind.storage:     return (name in t.storage) !is null;
    case RefKind.snapshot:    return (name in t.snapshots) !is null;
    case RefKind.capability:  return (name in t.capabilities) !is null;
    case RefKind.object:      return (name in t.objects) !is null;
    }
}

string refKindSection(RefKind rk)
{
    final switch (rk)
    {
    case RefKind.none:        return "";
    case RefKind.identity:    return "identities";
    case RefKind.namespace:   return "namespaces";
    case RefKind.service:     return "services";
    case RefKind.ipc:         return "ipc";
    case RefKind.storage:     return "storage";
    case RefKind.snapshot:    return "snapshots";
    case RefKind.capability:  return "capabilities";
    case RefKind.object:      return "objects";
    }
}

// ── Stage 4: resolve references ──────────────────────────────────────────────
// Walk the document against the schema; every string annotated refKind must
// name an existing entity.  A bare "$name" in objects-referencing fields also
// resolves.  Reports dangling refs with exact paths.
void resolveReferences(const ref JSONValue doc, const ref NameTables t,
                       ref CompileError[] errors)
{
    auto schema = documentSchema();
    walkRefs(doc, schema, "", t, errors);
}

private void walkRefs(const ref JSONValue v, const ref SchemaNode n, string path,
                      const ref NameTables t, ref CompileError[] errors)
{
    final switch (n.kind)
    {
    case SchemaKind.objectK:
        if (v.type != JSONType.object) return;
        foreach (k, val; v.object)
        {
            string cp = path.length ? path ~ "." ~ k : k;
            if (auto p = k in n.props) walkRefs(val, *p, cp, t, errors);
        }
        break;
    case SchemaKind.arrayK:
        if (v.type != JSONType.array) return;
        if (!n.items) break;
        foreach (i, elem; v.array)
            walkRefs(elem, *n.items, format("%s[%d]", path, i), t, errors);
        break;
    case SchemaKind.stringK:
        if (n.refKind != RefKind.none && v.type == JSONType.string)
        {
            string name = v.str;
            if (name.length && name[0] == '$') name = name[1 .. $]; // $objref
            if (!nameExists(t, n.refKind, name))
            {
                CompileError e;
                e.path = path;
                e.message = format("references unknown %s '%s'",
                                   refKindSection(n.refKind), v.str);
                errors ~= e;
            }
        }
        break;
    case SchemaKind.refK:
        if (v.type == JSONType.string && !nameExists(t, n.refKind, v.str))
        {
            CompileError e;
            e.path = path;
            e.message = format("references unknown %s '%s'",
                               refKindSection(n.refKind), v.str);
            errors ~= e;
        }
        break;
    case SchemaKind.enumK:    break;
    case SchemaKind.intK:     break;
    case SchemaKind.boolK:    break;
    case SchemaKind.colorK:   break;
    case SchemaKind.freeK:    break;
    }
}

// ── Stage 5: assign stable object IDs ─────────────────────────────────────────
// Deterministic dense ids in fixed order (spec §3 Stage 5):
// system → objects → namespaces → identities → services → processes →
// ipc → storage → snapshots → capabilities.  Two compiles → byte-identical ids.
ObjectNode[] assignIds(const ref JSONValue doc)
{
    ObjectNode[] nodes;
    uint next = 1;

    void emit(ObjKind k, string name, string objType, string section,
              uint idx, JSONValue payload)
    {
        ObjectNode n;
        n.id = next++;
        n.kind = k; n.name = name; n.objType = objType;
        n.section = section; n.index = idx; n.payload = payload;
        n.source = format("%s%s%s", section, idx == uint.max ? "" : "[",
                          idx == uint.max ? "" : to!string(idx) ~ "]");
        nodes ~= n;
    }

    if (auto s = "system" in doc.object)
        emit(ObjKind.system, "system", "Directory", "system", uint.max, *s);
    if (auto o = "objects" in doc.object)
        if (o.type == JSONType.object)
            foreach (k, v; o.object)
            {
                string t = "Directory";
                if (v.type == JSONType.object && "_type" in v.object)
                    t = v.object["_type"].str;
                emit(ObjKind.object, k, t, "objects", uint.max, v);
            }
    if (auto a = "namespaces" in doc.object)
        foreach (i, e; a.array)
            if (auto n = "name" in e.object) emit(ObjKind.namespace, n.str,
                "Namespace", "namespaces", to!uint(i), e);
    if (auto a = "identities" in doc.object)
        foreach (i, e; a.array)
            if (auto n = "name" in e.object) emit(ObjKind.identity, n.str,
                "Identity", "identities", to!uint(i), e);
    if (auto a = "services" in doc.object)
        foreach (i, e; a.array)
            if (auto n = "name" in e.object) emit(ObjKind.service, n.str,
                "Service", "services", to!uint(i), e);
    if (auto a = "processes" in doc.object)
        foreach (i, e; a.array)
            if (auto n = "name" in e.object) emit(ObjKind.process, n.str,
                "Process", "processes", to!uint(i), e);
    if (auto a = "ipc" in doc.object)
        foreach (i, e; a.array)
            if (auto n = "name" in e.object) emit(ObjKind.ipc, n.str,
                "Endpoint", "ipc", to!uint(i), e);
    if (auto a = "storage" in doc.object)
        foreach (i, e; a.array)
            if (auto n = "name" in e.object) emit(ObjKind.storage, n.str,
                "File", "storage", to!uint(i), e);
    if (auto a = "snapshots" in doc.object)
        foreach (i, e; a.array)
            if (auto n = "name" in e.object) emit(ObjKind.snapshot, n.str,
                "Generation", "snapshots", to!uint(i), e);
    if (auto c = "capabilities" in doc.object)
        if (c.type == JSONType.object)
        {
            // deterministic: by sorted key
            auto keys = appender!(string[]);
            foreach (k, _; c.object) keys ~= k;
            keys.data.sort();
            foreach (k; keys.data)
                emit(ObjKind.capability, k, "Capability", "capabilities", uint.max,
                     c.object[k]);
        }
    return nodes;
}

// ── Stage 6: detect cycles (3-color DFS over 4 edge sets) ─────────────────────
enum Color : ubyte { WHITE, GRAY, BLACK }

void detectCycles(const ref JSONValue doc, ref CompileError[] errors)
{
    // Each edge set is name → successor names; runCycleDFS does the 3-color
    // walk over it.  Four independent cycle domains (spec §3 Stage 6):
    // services: depends[] ∪ after[]
    detectNamedCycles(doc, "services", ["depends", "after"], "service dependency", errors);
    // namespaces: inherits
    detectNamedCycles(doc, "namespaces", ["inherits"], "namespace inheritance", errors);
    // snapshots: base
    detectNamedCycles(doc, "snapshots", ["base"], "snapshot base", errors);
    // capabilities: inherits (object map, not array)
    detectCapInheritsCycle(doc, errors);
}

private void detectNamedCycles(const ref JSONValue doc, string section,
                               string[] edgeFields, string label,
                               ref CompileError[] errors)
{
    if (auto a = section in doc.object)
        if (a.type == JSONType.array)
        {
            string[][string] adj;     // node → successors
            string[string] nodeOfIdx;  // idx → name (for error paths)
            foreach (i, e; a.array)
            {
                if (e.type != JSONType.object) continue;
                string name;
                if (auto n = "name" in e.object) name = n.str;
                if (name.length == 0) continue;
                nodeOfIdx[to!string(i)] = name;
                if (auto ex = name in adj) {} else adj[name] = [];
                foreach (ef; edgeFields)
                {
                    if (auto f = ef in e.object)
                    {
                        if (f.type == JSONType.array)
                        {
                            foreach (d; f.array)
                            {
                                if (d.type == JSONType.string)
                                    adj[name] ~= d.str;
                            }
                        }
                        else if (f.type == JSONType.string)
                        {
                            adj[name] ~= f.str;
                        }
                    }
                }
            }
            runCycleDFS(adj, label, errors);
        }
}

private void detectCapInheritsCycle(const ref JSONValue doc, ref CompileError[] errors)
{
    if (auto c = "capabilities" in doc.object)
        if (c.type == JSONType.object)
        {
            string[][string] adj;
            foreach (k, v; c.object)
            {
                if (k in adj) {} else adj[k] = [];
                if (v.type == JSONType.object)
                    if (auto inh = "inherits" in v.object)
                        if (inh.type == JSONType.string && inh.str.length)
                            adj[k] ~= inh.str;
            }
            runCycleDFS(adj, "capability inheritance", errors);
        }
}

// 3-color DFS.  On a GRAY back-edge, report the cycle path pinpointed.
private void runCycleDFS(ref string[][string] adj, string label,
                         ref CompileError[] errors)
{
    Color[string] color;
    string[] stack;
    bool cycleFound = false;
    foreach (n, _; adj) color[n] = Color.WHITE;

    bool dfs(string n)
    {
        color[n] = Color.GRAY;
        stack ~= n;
        if (auto succ = n in adj)
            foreach (m; *succ)
            {
                if (m !in color) continue; // dangling ref already reported in Stage 4
                if (color[m] == Color.GRAY)
                {
                    // closing edge n → m: build the cycle path m..n -> m
                    string[] path;
                    bool started = false;
                    foreach (s; stack)
                    {
                        if (s == m) started = true;
                        if (started) path ~= s;
                    }
                    path ~= m;
                    CompileError e;
                    e.path = label;
                    e.message = format("%s cycle: %s", label, path.joiner(" -> ").array.to!string);
                    errors ~= e;
                    cycleFound = true;
                    return true;
                }
                if (color[m] == Color.WHITE)
                    if (dfs(m)) return true;
            }
        stack = stack[0 .. $ - 1];
        color[n] = Color.BLACK;
        return false;
    }

    // deterministic start order: sorted node names
    auto keys = appender!(string[]);
    foreach (n, _; adj) keys ~= n;
    keys.data.sort();
    foreach (n; keys.data)
        if (color[n] == Color.WHITE)
            if (dfs(n)) break;
}

// ── Stage 7: check capabilities (subset narrowing + ceiling) ──────────────────
void checkCapabilities(const ref JSONValue doc, const ref NameTables t,
                       ref CapEntry[string] manifest, ref CompileError[] errors)
{
    if (auto c = "capabilities" in doc.object)
        if (c.type == JSONType.object)
        {
            // resolve each cap's mask (with inheritance), detecting supersets
            bool[string] resolving; // cycle guard within lattice walk
            uint resolveCap(string name, string originPath)
            {
                if (auto cached = name in manifest) return cached.mask;
                if (auto v = name in c.object)
                {
                    if (v.type != JSONType.object) return 0;
                    string[] rights;
                    if (auto r = "rights" in v.object)
                        if (r.type == JSONType.array)
                            foreach (x; r.array) if (x.type == JSONType.string) rights ~= x.str;
                    uint mask; string[] unknown;
                    resolveRights(rights, mask, unknown);
                    foreach (u; unknown)
                    {
                        CompileError e;
                        e.path = format("capabilities.%s.rights", name);
                        e.message = format("unknown right '%s'", u);
                        errors ~= e;
                    }
                    string parent;
                    if (auto inh = "inherits" in v.object)
                        if (inh.type == JSONType.string) parent = inh.str;
                    if (parent.length)
                    {
                        if (parent !in c.object)
                        {
                            CompileError e;
                            e.path = format("capabilities.%s.inherits", name);
                            e.message = format("inherits unknown capability '%s'", parent);
                            errors ~= e;
                        }
                        else
                        {
                            if (name in resolving)
                            {
                                // cycle already reported in Stage 6; skip
                            }
                            else
                            {
                                resolving[name] = true;
                                uint pmask = resolveCap(parent,
                                    format("capabilities.%s.inherits", name));
                                resolving.remove(name);
                                if (!isSubset(mask, pmask))
                                {
                                    uint excess = mask & ~pmask;
                                    CompileError e;
                                    e.path = format("capabilities.%s", name);
                                    e.message = format(
                                        "rights %s exceed inherited parent '%s' (privilege escalation rejected, §8)",
                                        rightsNames(excess), parent);
                                    errors ~= e;
                                }
                                mask &= pmask; // narrowing meet
                            }
                        }
                    }
                    CapEntry ce;
                    ce.name = name; ce.mask = mask; ce.parent = parent;
                    ce.bits = rightsNames(mask);
                    manifest[name] = ce;
                    return mask;
                }
                return 0;
            }

            foreach (k, _; c.object) resolveCap(k, format("capabilities.%s", k));
        }

    // service rights ⊆ identity ceiling
    if (auto svcs = "services" in doc.object)
        if (svcs.type == JSONType.array)
            foreach (i, s; svcs.array)
            {
                if (s.type != JSONType.object) continue;
                string sname; if (auto n = "name" in s.object) sname = n.str;
                string idName; if (auto id = "identity" in s.object) idName = id.str;
                string ceiling;
                if (idName.length && idName in t.identities)
                    if (auto idArr = "identities" in doc.object)
                        foreach (ie; idArr.array)
                            if (ie.type == JSONType.object)
                                if (auto nn = "name" in ie.object)
                                    if (nn.str == idName)
                                        if (auto rc = "rightsCeiling" in ie.object)
                                            ceiling = rc.str;
                if (!ceiling.length) continue;
                uint cmask = (ceiling in manifest) ? manifest[ceiling].mask : 0;
                // gather service held rights
                string[] held;
                if (auto caps = "capabilities" in s.object)
                    if (caps.type == JSONType.array)
                        foreach (x; caps.array)
                            if (x.type == JSONType.string) held ~= x.str;
                uint hmask = 0;
                foreach (h; held)
                    if (auto m = h in manifest) hmask |= m.mask;
                if (!isSubset(hmask, cmask))
                {
                    uint excess = hmask & ~cmask;
                    CompileError e;
                    e.path = format("services[%d].capabilities", i);
                    e.message = format(
                        "service '%s' holds rights %s exceeding its identity '%s' ceiling '%s' (privilege escalation rejected, §8)",
                        sname, rightsNames(excess), idName, ceiling);
                    errors ~= e;
                }
            }
}

// ── Phase 4: service graph + topological startup order (Kahn) ─────────────────
string[string] buildServiceGraph(const ref JSONValue doc)
{
    string[string] g;
    if (auto a = "services" in doc.object)
        if (a.type == JSONType.array)
            foreach (e; a.array)
            {
                if (e.type != JSONType.object) continue;
                string name; if (auto n = "name" in e.object) name = n.str;
                if (!name.length) continue;
                string[] succ;
                foreach (ef; ["depends", "after"])
                    if (auto f = ef in e.object)
                    {
                        if (f.type == JSONType.array)
                            foreach (d; f.array)
                                if (d.type == JSONType.string) succ ~= d.str;
                    }
                // dedup preserving order
                string[] dd;
                foreach (s; succ) if (!canFind(dd, s)) dd ~= s;
                g[name] = dd.joiner(",").array.to!string;
            }
    return g;
}

// Kahn's topological sort with declaration order as deterministic tie-break.
string[] topologicalOrder(const ref JSONValue doc, ref string[] errs)
{
    string[] order; // declaration order
    string[][string] succ; // name → depends∪after
    string[][string] pred; // name → who depends on it
    int[string] indeg;
    if (auto a = "services" in doc.object)
        if (a.type == JSONType.array)
        {
            foreach (e; a.array)
            {
                if (e.type != JSONType.object) continue;
                string name; if (auto n = "name" in e.object) name = n.str;
                if (!name.length) continue;
                if (name !in indeg) { indeg[name] = 0; order ~= name; }
                foreach (ef; ["depends", "after"])
                    if (auto f = ef in e.object)
                        if (f.type == JSONType.array)
                            foreach (d; f.array)
                                if (d.type == JSONType.string && d.str.length)
                                {
                                    if (d.str == name)
                                    {
                                        errs ~= format("service '%s' depends on itself", name);
                                        continue;
                                    }
                                    if (d.str !in indeg) { indeg[d.str] = 0; }
                                    succ[name] ~= d.str;
                                    pred[d.str] ~= name;
                                    indeg[name] += 1; // name waits on d.str
                                }
            }
            // Kahn with declaration-order queue
            string[] result;
            string[] ready;
            foreach (n; order) if ((n in indeg) && indeg[n] == 0) ready ~= n;
            size_t qi = 0;
            while (qi < ready.length)
            {
                string n = ready[qi++];
                result ~= n;
                if (auto pp = n in pred)
                    foreach (p; *pp)
                    {
                        if (auto ip = p in indeg)
                        {
                            *ip -= 1;
                            if (*ip == 0) ready ~= p;
                        }
                    }
            }
            if (result.length != order.length)
                errs ~= format("unsatisfiable service startup order (%d of %d started) - cycle was missed by Stage 6",
                               result.length, order.length);
            return result;
        }
    return [];
}

// ── Phase 5: identity + namespace tables ──────────────────────────────────────
IdentityRecFields[string] buildIdentityTable(const ref JSONValue doc)
{
    IdentityRecFields[string] tab;
    if (auto a = "identities" in doc.object)
        if (a.type == JSONType.array)
            foreach (e; a.array)
            {
                if (e.type != JSONType.object) continue;
                IdentityRecFields r;
                if (auto n = "name" in e.object) r.name = n.str;
                if (auto c = "color" in e.object) r.color = parseColor(c.str);
                if (auto t = "trust" in e.object) r.trust = t.str;
                if (auto rc = "rightsCeiling" in e.object) r.rightsCeiling = rc.str;
                if (auto ns = "namespace" in e.object) r.namespace_ = ns.str;
                if (auto net = "net" in e.object) r.net = net.str;
                if (auto clip = "clip" in e.object) r.clip = clip.str;
                if (auto gui = "gui" in e.object)
                    if (gui.type == JSONType.array)
                        foreach (g; gui.array) if (g.type == JSONType.string) r.gui ~= g.str;
                if (auto dev = "devices" in e.object)
                    if (dev.type == JSONType.array)
                        foreach (d; dev.array) if (d.type == JSONType.string) r.devices ~= d.str;
                if (auto dp = "disposable" in e.object) r.disposable = dp.boolean;
                if (auto tpl = "template" in e.object) r.template_ = tpl.str;
                if (r.name.length) tab[r.name] = r;
            }
    return tab;
}

// DOMAIN_MANAGER DM1: lower the domains[] section into a name→DomainRecFields table.
DomainRecFields[string] buildDomainTable(const ref JSONValue doc)
{
    DomainRecFields[string] tab;
    if (auto a = "domains" in doc.object)
        if (a.type == JSONType.array)
            foreach (e; a.array)
            {
                if (e.type != JSONType.object) continue;
                DomainRecFields r;
                if (auto n = "name" in e.object) r.name = n.str;
                if (auto t = "type" in e.object) r.type_ = t.str;
                if (auto id = "identity" in e.object) r.identity = id.str;
                if (auto tpl = "template" in e.object) r.template_ = tpl.str;
                if (auto ps = "persist" in e.object) r.persist = ps.str;
                if (r.name.length) tab[r.name] = r;
            }
    return tab;
}

NamespaceRecFields[string] buildNamespaceTable(const ref JSONValue doc)
{
    NamespaceRecFields[string] tab;
    if (auto a = "namespaces" in doc.object)
        if (a.type == JSONType.array)
            foreach (e; a.array)
            {
                if (e.type != JSONType.object) continue;
                NamespaceRecFields r;
                if (auto n = "name" in e.object) r.name = n.str;
                if (auto rt = "root" in e.object) r.root = rt.str;
                if (auto ih = "inherits" in e.object) r.inherits = ih.str;
                if (auto iso = "isolated" in e.object) r.isolated = iso.boolean;
                if (r.name.length) tab[r.name] = r;
            }
    return tab;
}

// "#RRGGBB" → 0xFFRRGGBB ; "#AARRGGBB" → as-is.  Mirrors IdentityColor packing.
uint parseColor(string s)
{
    if (s.length == 7) s = "#FF" ~ s[1 .. $]; // add opaque alpha
    if (s.length != 9) return 0xFF000000;
    return to!uint(s[1 .. $], 16);
}

// ── Phase 7: materialize IPC rules ────────────────────────────────────────────
IpcRule[] buildIpcRules(const ref JSONValue doc, const ref NameTables t,
                        ref CompileError[] errors)
{
    IpcRule[] rules;
    if (auto a = "ipc" in doc.object)
        if (a.type == JSONType.array)
            foreach (pi, p; a.array)
            {
                if (p.type != JSONType.object) continue;
                string policy; if (auto n = "name" in p.object) policy = n.str;
                bool dh; if (auto d = "dh" in p.object) dh = d.boolean;
                bool audit = true; if (auto au = "audit" in p.object) audit = au.boolean;
                string broker; if (auto b = "keyBroker" in p.object) broker = b.str;
                if (auto al = "allow" in p.object)
                    if (al.type == JSONType.array)
                        foreach (ai, pair; al.array)
                        {
                            if (pair.type != JSONType.object) continue;
                            IpcRule r;
                            r.policy = policy; r.dh = dh; r.audit = audit; r.broker = broker;
                            if (auto f = "from" in pair.object) r.fromId = f.str;
                            if (auto tt = "to" in pair.object) r.toId = tt.str;
                            if (auto bb = "broker" in pair.object) r.broker = bb.str;
                            rules ~= r;
                        }
            }
    return rules;
}

// ── Phase 8: boot plan (spec §4 kernel/userspace split) ────────────────────────
BootStep[] buildBootPlan(const ref JSONValue doc, const string[] startupOrder)
{
    BootStep[] plan;
    // Phase: trusted (kernel-side, early)
    {
        BootStep s; s.phase = "trusted"; s.kind = "read-bundle-member";
        s.target = "/system.json"; s.note = "kernel reads named bundle member";
        plan ~= s;
    }
    {
        BootStep s; s.phase = "trusted"; s.kind = "verify-signature";
        s.target = "boot.signature"; s.note = "HMAC-SHA-256 over canonical JSON";
        plan ~= s;
    }
    if (auto sys = "system" in doc.object)
        if (sys.type == JSONType.object)
            if (auto g = "generation" in sys.object)
            {
                BootStep s; s.phase = "trusted"; s.kind = "select-generation";
                s.target = to!string(g.integer); s.note = "system.generation → slotActive()";
                plan ~= s;
            }
    {
        BootStep s; s.phase = "trusted"; s.kind = "measure"; s.target = "boot.measured";
        s.note = "arm boot-success auto-rollback counter";
        plan ~= s;
    }
    // Phase: object-tree (user-space init): objAlloc every declared object
    foreach (n; ["objects", "namespaces", "identities", "storage", "snapshots"])
        if (auto a = n in doc.object)
        {
            BootStep s; s.phase = "object-tree"; s.kind = "objAlloc";
            s.target = n; s.note = format("materialize %s objects", n);
            plan ~= s;
        }
    {
        BootStep s; s.phase = "object-tree"; s.kind = "identityFreeze";
        s.target = "identities"; s.note = "registry immutable after policy load";
        plan ~= s;
    }
    // Phase: services (dependency-ordered start)
    {
        BootStep s; s.phase = "services"; s.kind = "serviceStartAll";
        string joined;
        foreach (i, n; startupOrder) { if (i) joined ~= ","; joined ~= n; }
        s.target = joined;
        s.note = "topological start order";
        plan ~= s;
    }
    {
        BootStep s; s.phase = "services"; s.kind = "install-ipc-rules";
        s.target = "ipc"; s.note = "deny-by-default IpcPairRule rows";
        plan ~= s;
    }
    return plan;
}

// ── Phase 11: classify each section live vs reboot (§13 table) ─────────────────
LiveClass[string] classifyLive(const ref JSONValue doc)
{
    LiveClass[string] t;
    t["gui"] = LiveClass.live;
    t["logging"] = LiveClass.live;
    t["ipc"] = LiveClass.live;
    if ("services" in doc.object) t["services"] = LiveClass.live; // add/remove/restart live
    if ("networking" in doc.object) t["networking"] = LiveClass.live;
    t["security"] = LiveClass.live; // profiles live; immutableImage reboot (per-field)
    t["kernel"] = LiveClass.reboot;
    t["boot"] = LiveClass.reboot;
    t["system"] = LiveClass.reboot;
    t["namespaces"] = LiveClass.reboot;
    t["compatibility"] = LiveClass.reboot;
    t["distributed"] = LiveClass.reboot;
    if ("identities" in doc.object) t["identities"] = LiveClass.reboot;
    if ("storage" in doc.object) t["storage"] = LiveClass.reboot;
    if ("snapshots" in doc.object) t["snapshots"] = LiveClass.reboot;
    return t;
}

private void emitWarnings(const ref JSONValue doc, ref string[] warnings)
{
    if (auto sec = "security" in doc.object)
        if (sec.type == JSONType.object)
            if (auto rl = "rootless" in sec.object)
                if (rl.type == JSONType.false_)
                    warnings ~= "security.rootless=false violates §17 constraint (stay rootless)";
}

// ── graph_to_dot: emit Graphviz DOT (spec §14 graph, orgctl conventions) ───────
string graphToDot(const ref CompiledGraph g)
{
    import std.string : format;
    auto b = appender!string;
    b.put("digraph anonymos {\n");
    b.put("  rankdir=LR;\n");
    b.put("  node [shape=record, fontname=\"Helvetica\"];\n");
    foreach (n; g.objects)
    {
        string label = format("{%d| %s\\n%s | %s}", n.id, n.name,
                              n.objType, n.section);
        b.put(format("  n%d [label=\"%s\"];\n", n.id, label));
    }
    // capability derivation edges
    foreach (name, ce; g.capabilityManifest)
    {
        if (!ce.parent.length) continue;
        // find ids by name+kind
        uint child = nodeId(g, ObjKind.capability, name);
        uint parent = nodeId(g, ObjKind.capability, ce.parent);
        if (child && parent)
            b.put(format("  n%d -> n%d [label=\"capDerive\", style=dashed];\n",
                         child, parent));
    }
    // service depends edges
    foreach (svc, depsStr; g.serviceGraph)
    {
        uint from = nodeId(g, ObjKind.service, svc);
        if (!from) continue;
        foreach (d; depsStr.splitter(","))
            if (d.length)
            {
                uint to = nodeId(g, ObjKind.service, d);
                if (to) b.put(format("  n%d -> n%d [label=\"depends\"];\n", from, to));
            }
    }
    // namespace inherits
    foreach (ns, rec; g.namespaceTable)
    {
        if (!rec.inherits.length) continue;
        uint from = nodeId(g, ObjKind.namespace, ns);
        uint to = nodeId(g, ObjKind.namespace, rec.inherits);
        if (from && to)
            b.put(format("  n%d -> n%d [label=\"inherits\"];\n", from, to));
    }
    // ipc allow edges (identity → identity)
    foreach (r; g.ipcRules)
    {
        uint from = nodeId(g, ObjKind.identity, r.fromId);
        uint to = nodeId(g, ObjKind.identity, r.toId);
        if (from && to)
        {
            string lbl = "ipc";
            if (r.dh) lbl = "ipc:dh";
            b.put(format("  n%d -> n%d [label=\"%s\", color=blue];\n", from, to, lbl));
        }
    }
    b.put("}\n");
    return b.data;
}

private uint nodeId(const ref CompiledGraph g, ObjKind k, string name)
{
    foreach (n; g.objects)
        if (n.kind == k && n.name == name) return n.id;
    return 0;
}
