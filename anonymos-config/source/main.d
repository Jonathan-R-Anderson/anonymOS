// main.d — Phase 12/§14 CLI for anonymos-config.
// Drives the compiler (validator.d + modules.d + compiler.d) and the generation
// store (generations.d).  Subcommands map 1:1 to the spec's §14 table:
//   check system.json            parse+validate (Stages 1–7); print all errors
//   build system.json            check then write a new generation
//   diff old.json new.json       compile both; per-section changes + live/reboot
//   switch system.json           build then atomically genSetActive
//   rollback                     genRollback → parent generation
//   graph system.json            emit the object graph as Graphviz DOT
module anonymos.config.main;

import anonymos.config.schema;
import anonymos.config.validator;
import anonymos.config.modules;
import anonymos.config.compiler : CompiledGraph, ObjKind, compile, CompileError,
                                  classifyLive, graphToDot;
import anonymos.config.schema : LiveClass;
import anonymos.config.generations;
import anonymos.config.manifest;
import anonymos.config.caplattice;
import std.json;
import std.json;
import std.stdio;
import std.file;
import std.format;
import std.getopt;
import std.array;
import std.algorithm;
import std.conv;

int main(string[] args)
{
    if (args.length < 2) return usage();

    string cmd = args[1];
    string storeDir = getEnv("ANONYMOS_CONFIG_STORE", "./anonymos-generations");
    // getopt requires args[0] to be the program name; keep the real one and
    // pass the command's operands after it.
    string[] cmdArgs = [args[0]] ~ args[2 .. $];

    try
    {
        switch (cmd)
        {
        case "check":     return cmdCheck(cmdArgs, storeDir);
        case "build":     return cmdBuild(cmdArgs, storeDir);
        case "diff":      return cmdDiff(cmdArgs, storeDir);
        case "switch":    return cmdSwitch(cmdArgs, storeDir);
        case "rollback":  return cmdRollback(cmdArgs, storeDir);
        case "graph":     return cmdGraph(cmdArgs, storeDir);
        case "schema":    return cmdSchema(cmdArgs); // export the JSON schema
        case "emit-manifest":  return cmdEmitManifest(cmdArgs); // §4 binary lowering
        case "help": case "--help": case "-h": return usage();
        default:
            stderr.writeln("anonymos-config: unknown command '", cmd, "'");
            return usage();
        }
    }
    catch (Exception e)
    {
        stderr.writeln("anonymos-config: ", e.msg);
        return 2;
    }
}

int usage()
{
    writeln("anonymos-config — declarative system configuration compiler");
    writeln("usage: anonymos-config <command> [options]");
    writeln("commands:");
    writeln("  check system.json        parse + validate + compile; report all errors");
    writeln("  build system.json        check then write a new generation");
    writeln("  diff old.json new.json   per-section changes, labelled live/reboot");
    writeln("  switch system.json       build then atomically activate generation");
    writeln("  rollback                 activate the parent of the current generation");
    writeln("  graph system.json        emit the compiled object graph as DOT");
    writeln("  schema                   emit the JSON-Schema document");
    writeln("options:");
    writeln("  --store <dir>            generation store (default ./anonymos-generations or $ANONYMOS_CONFIG_STORE)");
    writeln("  -q                       quiet: print only errors");
    return 0;
}

enum cmdOk = 0;
enum cmdFail = 1;

// Load (with imports) + parse + validate + compile.  Returns the compiled graph
// on success; on any failure prints errors and returns null.  Shared by the
// read-then-act subcommands.
bool loadAndCompile(string path, out CompiledGraph g, out JSONValue doc,
                    bool quiet)
{
    doc = JSONValue.init;
    g = CompiledGraph.init;

    // Stage 1+3: load with imports merged.
    JSONValue merged;
    ModuleError merr;
    if (!loadWithImports(path, merged, merr))
    {
        stderr.writeln(merr.toString());
        return false;
    }
    doc = merged;

    // Stage 2: structural validation (collect-all).
    auto verrs = validate(doc);
    foreach (e; verrs) stderr.writeln(e.toString());

    // Stages 4–8: compile.
    CompileError[] cerrs;
    if (!compile(doc, g, cerrs))
        foreach (e; cerrs) stderr.writeln(e.toString());

    if (verrs.length || cerrs.length)
    {
        if (!quiet)
            stderr.writeln(format("(anonymos-config: %d validation + %d compile errors)",
                                  verrs.length, cerrs.length));
        return false;
    }
    return true;
}

private int cmdCheck(string[] args, string storeDir)
{
    string path;
    bool quiet;
    auto help = getopt(args, "store", &storeDir, "q|quiet", &quiet);
    if (args.length < 2) // args[0] is the program name
    {
        stderr.writeln("usage: anonymos-config check <system.json>");
        return cmdFail;
    }
    path = args[1];

    CompiledGraph g;
    JSONValue doc;
    if (!loadAndCompile(path, g, doc, quiet)) return cmdFail;

    // Stitch a configHash into the graph for display.
    g.configHash = configHashOf(doc);

    writeln("OK: ", path);
    writeln(format("  objects: %d", g.objects.length));
    writeln(format("  services: %d (startup order: %s)", g.startupOrder.length,
                   g.startupOrder.length ? g.startupOrder.joiner(", ").array : "(none)"));
    writeln(format("  identities: %d", countByKind(g, ObjKind.identity)));
    writeln(format("  namespaces: %d", countByKind(g, ObjKind.namespace)));
    writeln(format("  capabilities: %d", g.capabilityManifest.length));
    writeln(format("  ipc rules: %d", g.ipcRules.length));
    writeln(format("  configHash: %s", g.configHash[0 .. 16]));
    foreach (w; g.warnings) writeln("  WARNING: ", w);
    return cmdOk;
}

private int cmdBuild(string[] args, string storeDir)
{
    string path;
    bool quiet;
    auto help = getopt(args, "store", &storeDir, "q|quiet", &quiet);
    if (args.length < 2)
    {
        stderr.writeln("usage: anonymos-config build <system.json>");
        return cmdFail;
    }
    path = args[1];

    CompiledGraph g;
    JSONValue doc;
    if (!loadAndCompile(path, g, doc, quiet)) return cmdFail;

    auto store = openStore(storeDir);
    string parent = currentGen(store);
    auto manifest = manifestJson(g);
    auto id = buildGeneration(store, doc, manifest, parent);
    writeln("built generation ", id);
    return cmdOk;
}

private int cmdDiff(string[] args, string storeDir)
{
    auto help = getopt(args, "store", &storeDir);
    if (args.length < 3) // args[0] is the program name
    {
        stderr.writeln("usage: anonymos-config diff <old.json> <new.json>");
        return cmdFail;
    }
    CompiledGraph ga, gb;
    JSONValue da, db;
    if (!loadAndCompile(args[1], ga, da, true)) return cmdFail;
    if (!loadAndCompile(args[2], gb, db, true)) return cmdFail;

    // Per-section structured diff with live/reboot labels.
    auto keys = appender!(string[]);
    foreach (k, _; da.object) keys ~= k;
    foreach (k, _; db.object) if (k !in da.object) keys ~= k;
    keys.data.sort();

    bool any = false;
    foreach (k; keys.data)
    {
        bool inA = (k in da.object) !is null;
        bool inB = (k in db.object) !is null;
        string va = inA ? toJSON(da.object[k], false) : "";
        string vb = inB ? toJSON(db.object[k], false) : "";
        if (va != vb)
        {
            any = true;
            string change = !inA ? "added" : (!inB ? "removed" : "changed");
            string klass = liveOrReboot(k);
            writeln(format("%-14s %-8s %s", k, klass, change));
        }
    }
    if (!any) writeln("(no differences)");
    return cmdOk;
}

private int cmdSwitch(string[] args, string storeDir)
{
    string path;
    bool quiet;
    auto help = getopt(args, "store", &storeDir, "q|quiet", &quiet);
    if (args.length < 2)
    {
        stderr.writeln("usage: anonymos-config switch <system.json>");
        return cmdFail;
    }
    path = args[1];

    CompiledGraph g;
    JSONValue doc;
    if (!loadAndCompile(path, g, doc, quiet)) return cmdFail;

    auto store = openStore(storeDir);
    string parent = currentGen(store);
    auto manifest = manifestJson(g);
    auto id = buildGeneration(store, doc, manifest, parent);
    if (!switchTo(store, id))
    {
        stderr.writeln("switch failed (generation missing?)");
        return cmdFail;
    }
    // Report what was applied live vs armed for reboot (§11/§13).
    writeln("switched to generation ", id);
    writeln("  live-applied: ", liveSections(g).joiner(", ").array);
    writeln("  armed-for-reboot: ", rebootSections(g).joiner(", ").array);
    return cmdOk;
}

private int cmdRollback(string[] args, string storeDir)
{
    auto help = getopt(args, "store", &storeDir);
    auto store = openStore(storeDir);
    bool ok;
    auto to = rollback(store, ok);
    if (!ok)
    {
        stderr.writeln("rollback failed (no current generation or no parent)");
        return cmdFail;
    }
    writeln("rolled back to generation ", to);
    return cmdOk;
}

private int cmdGraph(string[] args, string storeDir)
{
    bool quiet;
    auto help = getopt(args, "store", &storeDir, "q|quiet", &quiet);
    if (args.length < 2)
    {
        stderr.writeln("usage: anonymos-config graph <system.json>");
        return cmdFail;
    }
    CompiledGraph g;
    JSONValue doc;
    if (!loadAndCompile(args[1], g, doc, quiet)) return cmdFail;
    write(graphToDot(g));
    return cmdOk;
}

private int cmdSchema(string[] args)
{
    auto s = exportJsonSchema();
    writeln(toJSON(s, true));
    return cmdOk;
}

// emit-manifest: lower a compiled config to the parser-free binary boot manifest
// (spec §4 lowering channel).  Writes manifest.blob to stdout (or a path with -o).
// Records are emitted in kernel-apply order: namespaces → identities → freeze →
// services (register) → service deps → serviceStartAll → genSetActive.
private int cmdEmitManifest(string[] args)
{
    string outPath;
    auto help = getopt(args, "o|output", &outPath);
    if (args.length < 2)
    {
        stderr.writeln("usage: anonymos-config emit-manifest [-o manifest.blob] <system.json>");
        return cmdFail;
    }
    CompiledGraph g;
    JSONValue doc;
    if (!loadAndCompile(args[1], g, doc, false)) return cmdFail;

    auto blob = buildManifest(g, doc);
    if (outPath.length)
    {
        import std.file : write;
        std.file.write(outPath, cast(byte[]) blob);
        writeln(format("wrote %d-byte signed manifest to %s (%d services, %d identities)",
                       blob.length, outPath,
                       countByKind(g, ObjKind.service), countByKind(g, ObjKind.identity)));
    }
    else
    {
        import std.stdio : stdout, write;
        stdout.rawWrite(cast(byte[]) blob);
    }
    return cmdOk;
}

// Build the full signed manifest blob from a compiled graph (delegated to the
// manifest module's serializer; defined there so both the CLI and the test
// suite share one implementation).
// ── helpers ──────────────────────────────────────────────────────────────────
private size_t countByKind(const ref CompiledGraph g, ObjKind k)
{
    size_t n;
    foreach (o; g.objects) if (o.kind == k) ++n;
    return n;
}

private string[] liveSections(const ref CompiledGraph g)
{
    string[] r;
    foreach (k, c; g.liveReconfig) if (c == LiveClass.live) r ~= k;
    r.sort();
    return r;
}

private string[] rebootSections(const ref CompiledGraph g)
{
    string[] r;
    foreach (k, c; g.liveReconfig) if (c == LiveClass.reboot) r ~= k;
    r.sort();
    return r;
}

private string liveOrReboot(string section)
{
    foreach (live; ["gui", "logging", "ipc", "networking", "services", "security"])
        if (section == live) return "live";
    return "reboot";
}

// Render the compiled graph as a manifest JSON (written into the generation).
private string manifestJson(const ref CompiledGraph g)
{
    auto o = JSONValue(string[string].init);
    o.object["configHash"] = JSONValue(g.configHash.length ? g.configHash : "");

    auto objs = JSONValue(string[].init);
    foreach (n; g.objects)
    {
        auto on = JSONValue(string[string].init);
        on.object["id"] = JSONValue(to!string(n.id));
        on.object["name"] = JSONValue(n.name);
        on.object["objType"] = JSONValue(n.objType);
        on.object["section"] = JSONValue(n.section);
        objs.array ~= on;
    }
    o.object["objects"] = objs;

    auto order = JSONValue(string[].init);
    foreach (s; g.startupOrder) order.array ~= JSONValue(s);
    o.object["startupOrder"] = order;

    auto sg = JSONValue(string[string].init);
    foreach (k, v; g.serviceGraph) sg.object[k] = JSONValue(v);
    o.object["serviceGraph"] = sg;

    auto caps = JSONValue(string[string].init);
    foreach (name, ce; g.capabilityManifest)
    {
        auto c = JSONValue(string[string].init);
        c.object["mask"] = JSONValue(format("0x%x", ce.mask));
        c.object["parent"] = JSONValue(ce.parent);
        auto bits = JSONValue(string[].init);
        foreach (b; ce.bits) bits.array ~= JSONValue(b);
        c.object["bits"] = bits;
        caps.object[name] = c;
    }
    o.object["capabilities"] = caps;

    auto ipc = JSONValue(string[].init);
    foreach (r; g.ipcRules)
    {
        auto rr = JSONValue(string[string].init);
        rr.object["policy"] = JSONValue(r.policy);
        rr.object["from"] = JSONValue(r.fromId);
        rr.object["to"] = JSONValue(r.toId);
        rr.object["broker"] = JSONValue(r.broker);
        rr.object["dh"] = JSONValue(r.dh);
        rr.object["audit"] = JSONValue(r.audit);
        ipc.array ~= rr;
    }
    o.object["ipc"] = ipc;

    auto lr = JSONValue(string[string].init);
    foreach (k, c; g.liveReconfig)
        lr.object[k] = JSONValue(c == LiveClass.live ? "live" : "reboot");
    o.object["liveReconfig"] = lr;

    auto bp = JSONValue(string[].init);
    foreach (s; g.bootPlan)
    {
        auto bs = JSONValue(string[string].init);
        bs.object["phase"] = JSONValue(s.phase);
        bs.object["kind"] = JSONValue(s.kind);
        bs.object["target"] = JSONValue(s.target);
        bs.object["note"] = JSONValue(s.note);
        bp.array ~= bs;
    }
    o.object["bootPlan"] = bp;

    return toJSON(o, false);
}

string getEnv(string name, string fallback)
{
    import std.process : environment;
    return environment.get(name, fallback);
}
