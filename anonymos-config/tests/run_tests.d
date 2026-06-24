// run_tests.d — Phase 12 host test driver for anonymos-config.
// Mirrors the kernel's org_test.d style: a check() helper that counts
// pass/total, grouped by phase, printing a one-line summary at the end.
//
// Covers every phase the DECLARATIVE_CONFIG_SPEC.md §15–16 names:
//   P1 schema validation, P2 object graph ids, P3 imports+refs+cycles+caps,
//   P4 service graph+topo order, P5 identity/namespace, P6 capability lattice,
//   P7 IPC rules, P8 generations build/switch/rollback/diff, P9 colors,
//   P10 module merge, P11 live classification, P12 integration.
module anonymos.config.run_tests;

import anonymos.config.schema;
import anonymos.config.validator;
import anonymos.config.modules;
import anonymos.config.compiler;
import anonymos.config.caplattice;
import anonymos.config.generations;
import std.json;
import std.stdio;
import std.conv;
import std.file;
import std.path;
import std.format;
import std.algorithm.searching : canFind, any, startsWith;

int main()
{
    size_t pass, total;

    void check(bool cond, string label)
    {
        ++total;
        if (cond) { ++pass; }
        else { writefln("  FAIL: %s", label); }
    }

    // Helper: parse a JSON literal, asserting it parses.
    JSONValue j(string txt)
    {
        auto r = parseText(txt);
        assert(r.ok, "test fixture parse failed: " ~ r.error);
        return r.doc;
    }

    // ── Phase 1: schema validation (collect-all) ─────────────────────────────
    writeln("[P1] schema validation");
    {
        // every section present, valid doc → no errors
        auto doc = j(validDoc);
        auto errs = validate(doc);
        check(errs.length == 0, format("valid doc has no errors (got %d)", errs.length));

        // bad enum → reported with exact path
        auto bad = j(validDoc); bad.object["identities"].array[0].object["net"] = JSONValue("internet");
        auto be = validate(bad);
        check(be.any!(e => e.path.canFind("identities") && e.message.canFind("not one of")),
              "bad enum reported");

        // bad color → reported
        auto bc = j(validDoc); bc.object["identities"].array[1].object["color"] = JSONValue("blue");
        check(validate(bc).any!(e => e.message.canFind("not a valid")), "bad color reported");

        // unknown top-level key → reported (strict top level)
        auto bk = j(validDoc); bk.object["bogus"] = JSONValue(1);
        check(validate(bk).any!(e => e.path == "bogus" && e.message.canFind("unknown")),
              "unknown top-level key reported");

        // wrong type → reported
        auto bt = j(validDoc); bt.object["system"].object["generation"] = JSONValue("three");
        check(validate(bt).any!(e => e.message.canFind("expected integer")), "wrong type reported");

        // collect MULTIPLE errors in one pass (§12 fail once)
        auto multi = j(validDoc);
        multi.object["bogus"] = JSONValue(1);
        multi.object["identities"].array[0].object["trust"] = JSONValue("ninja");
        auto me = validate(multi);
        check(me.length >= 2, format("multiple errors collected at once (got %d)", me.length));

        // missing required field
        auto mr = j(validDoc); mr.object["identities"].array[0].object.remove("name");
        check(validate(mr).any!(e => e.message.canFind("missing required")), "missing required reported");

        // malformed JSON → fatal parse error (Stage 1)
        auto pr = parseText("{ not json");
        check(!pr.ok, "malformed JSON is a fatal parse error");
    }

    // ── Phase 2: object graph + stable deterministic ids ─────────────────────
    writeln("[P2] object graph ids");
    {
        auto doc = j(validDoc);
        auto a = assignIds(doc);
        auto b = assignIds(doc);
        check(a.length == b.length, "same doc → same object count");
        bool same = true;
        foreach (i, n; a) if (n.id != b[i].id || n.name != b[i].name) same = false;
        check(same, "stable ids: deterministic across compiles");
        // all 9 kinds represented (system/object/namespace/identity/service/
        // ipc/storage/snapshot/capability)
        bool[ObjKind] seen;
        foreach (n; a) seen[n.kind] = true;
        check(seen[ObjKind.system] && seen[ObjKind.object] && seen[ObjKind.namespace] &&
              seen[ObjKind.identity] && seen[ObjKind.service] && seen[ObjKind.ipc] &&
              seen[ObjKind.storage] && seen[ObjKind.snapshot] && seen[ObjKind.capability],
              "all 9 object kinds emitted");
        // id uniqueness
        bool uniq = true;
        uint[uint] ids;
        foreach (n; a) { if (n.id in ids) uniq = false; ids[n.id] = 1; }
        check(uniq, "object ids are unique");
    }

    // ── Phase 3: imports + references + cycle detection + capabilities ───────
    writeln("[P3] imports, references, cycles, capabilities");
    {
        // dangling reference (service depends on unknown) → Stage 4
        auto doc = j(validDoc);
        doc.object["services"].array[0].object["depends"] = parseJSON(`["nope"]`);
        CompileError[] cerrs; CompiledGraph g;
        compile(doc, g, cerrs);
        check(cerrs.any!(e => e.message.canFind("unknown service")), "dangling service ref reported");

        // service dependency cycle → Stage 6
        auto cyc = j(validDoc);
        cyc.object["services"] = parseJSON(`[
          {"name":"a","identity":"System","capabilities":["fs-rw"],"depends":["b"]},
          {"name":"b","identity":"System","capabilities":["fs-rw"],"depends":["a"]}]`);
        cerrs = null; compile(cyc, g, cerrs);
        check(cerrs.any!(e => e.path.canFind("service dependency") && e.message.canFind("cycle")),
              "service dependency cycle detected");

        // namespace inherits cycle
        auto nc = j(validDoc);
        nc.object["namespaces"] = parseJSON(`[
          {"name":"x","root":"$root","inherits":"y"},
          {"name":"y","root":"$root","inherits":"x"}]`);
        cerrs = null; compile(nc, g, cerrs);
        check(cerrs.any!(e => e.message.canFind("namespace inheritance") && e.message.canFind("cycle")),
              "namespace inheritance cycle detected");

        // snapshot base cycle
        auto sc = j(validDoc);
        sc.object["snapshots"] = parseJSON(`[
          {"name":"g1","base":"g2"},{"name":"g2","base":"g1"}]`);
        cerrs = null; compile(sc, g, cerrs);
        check(cerrs.any!(e => e.message.canFind("snapshot base") && e.message.canFind("cycle")),
              "snapshot base cycle detected");

        // capability inherits cycle + subset violation
        auto cc = j(validDoc);
        cc.object["capabilities"] = parseJSON(`{
          "a":{"inherits":"b","rights":["read"]},
          "b":{"inherits":"a","rights":["write"]}}`);
        cerrs = null; compile(cc, g, cerrs);
        check(cerrs.any!(e => e.message.canFind("capability inheritance") && e.message.canFind("cycle")),
              "capability inheritance cycle detected");

        // subset violation: child holds a right not in parent
        auto sv = j(validDoc);
        sv.object["capabilities"] = parseJSON(`{
          "base":{"rights":["read"]},
          "child":{"inherits":"base","rights":["write"]}}`);
        cerrs = null; compile(sv, g, cerrs);
        check(cerrs.any!(e => e.message.canFind("exceed inherited parent") &&
                          e.message.canFind("privilege escalation")),
              "cap subset violation rejected (§8)");

        // import cycle (a imports b imports a) — write temp files
        auto tmp = tempDir() ~ "/anom-test-cycle";
        mkdirRecurse(tmp);
        std.file.write(tmp ~ "/a.json", `{"imports":["b.json"],"system":{"name":"a"}}`);
        std.file.write(tmp ~ "/b.json", `{"imports":["a.json"],"system":{"name":"b"}}`);
        JSONValue merged; ModuleError merr;
        auto loaded = loadWithImports(tmp ~ "/a.json", merged, merr);
        check(!loaded && merr.message.canFind("cycle"), "import cycle detected");
    }

    // ── Phase 4: service graph + topological startup order ───────────────────
    writeln("[P4] service graph + topological order");
    {
        // diamond dependency: d depends on b,c; b,c depend on a → order starts a
        auto doc = j(validDoc);
        doc.object.remove("ipc"); // these tests exercise ordering, not ipc
        doc.object["services"] = parseJSON(`[
          {"name":"a","identity":"System","capabilities":["fs-rw"]},
          {"name":"b","identity":"System","capabilities":["fs-rw"],"depends":["a"]},
          {"name":"c","identity":"System","capabilities":["fs-rw"],"depends":["a"]},
          {"name":"d","identity":"System","capabilities":["fs-rw"],"depends":["b","c"]}]`);
        CompiledGraph g; CompileError[] cerrs;
        compile(doc, g, cerrs);
        check(cerrs.length == 0, "diamond deps compile clean");
        check(g.startupOrder.length == 4, "all 4 services in startup order");
        check(g.startupOrder[0] == "a", "diamond root 'a' starts first");
        size_t di; foreach (i, s; g.startupOrder) if (s == "d") di = i;
        check(di == 3, "diamond sink 'd' starts last");

        // after-only hint does NOT impose a hard dep (both can start in any order)
        auto after = j(validDoc);
        after.object.remove("ipc");
        after.object["services"] = parseJSON(`[
          {"name":"x","identity":"System","capabilities":["fs-rw"]},
          {"name":"y","identity":"System","capabilities":["fs-rw"],"after":["x"]}]`);
        cerrs = null; compile(after, g, cerrs);
        check(cerrs.length == 0, "after-only hint compiles (no hard dep)");

        // self-dependency rejected
        auto self = j(validDoc);
        self.object.remove("ipc");
        self.object["services"] = parseJSON(`[
          {"name":"s","identity":"System","capabilities":["fs-rw"],"depends":["s"]}]`);
        cerrs = null; compile(self, g, cerrs);
        check(cerrs.any!(e => e.message.canFind("depends on itself") ||
                              e.message.canFind("cycle")),
              "self-dependency rejected");
    }

    // ── Phase 5: identity + namespace tables ─────────────────────────────────
    writeln("[P5] identity + namespace");
    {
        auto doc = j(validDoc);
        CompiledGraph g; CompileError[] cerrs;
        compile(doc, g, cerrs);
        check(g.identityTable.length == 3, "3 identities materialized");
        check((g.identityTable)["Banking"].color == 0xFFE02020, "color #E02020 → 0xFFE02020 (opaque alpha)");
        check((g.identityTable)["Personal"].net == "nat", "net policy mapped");
        check((g.identityTable)["Banking"].clip == "deny", "clip policy mapped");
        check((g.identityTable)["Banking"].gui.length == 2, "gui flags mapped");
        check(g.namespaceTable.length == 3, "3 namespaces materialized");
        check((g.namespaceTable)["user-ns"].inherits == "system-ns", "namespace inherits mapped");

        // namespace inherits unknown → Stage 4
        auto bad = j(validDoc);
        bad.object["namespaces"].array[0].object["inherits"] = JSONValue("ghost");
        cerrs = null; compile(bad, g, cerrs);
        check(cerrs.any!(e => e.message.canFind("unknown namespace")), "namespace inherits-unknown reported");
    }

    // ── Phase 6: capability lattice ──────────────────────────────────────────
    writeln("[P6] capability lattice");
    {
        uint mask; string[] unk;
        check(resolveRights(["read", "write"], mask, unk) && mask == 0x3, "read|write = 0x3");
        check(resolveRights(["all"], mask, unk) && mask == CAP_RIGHT_ALL, "'all' = CAP_RIGHT_ALL fd universe");
        check(resolveRights(["bogus"], mask, unk) == false && unk == ["bogus"], "unknown right flagged");
        check(isSubset(0x3, 0x7) && !isSubset(0x8, 0x7), "subset narrowing predicate");
        // service rights ⊆ identity ceiling escalation rejected
        auto doc = j(validDoc);
        // Personal ceiling is fs-rw (read,write,stat); give a service under it 'call'
        doc.object["services"].array[0].object["identity"] = JSONValue("Personal");
        doc.object["services"].array[0].object["capabilities"] = parseJSON(`["call"]`);
        CompiledGraph g; CompileError[] cerrs;
        compile(doc, g, cerrs);
        check(cerrs.any!(e => e.message.canFind("exceeding its identity") &&
                              e.message.canFind("privilege escalation")),
              "service rights exceeding identity ceiling rejected (§8)");
    }

    // ── Phase 7: IPC rules ───────────────────────────────────────────────────
    writeln("[P7] IPC rules");
    {
        auto doc = j(validDoc);
        CompiledGraph g; CompileError[] cerrs;
        compile(doc, g, cerrs);
        check(g.ipcRules.length == 1, "1 IPC allow-pair materialized");
        check(g.ipcRules[0].fromId == "Personal" && g.ipcRules[0].toId == "System",
              "ipc from/to mapped");
        check(g.ipcRules[0].dh && g.ipcRules[0].audit, "ipc dh+audit flags carried");

        // allow references unknown identity → Stage 4
        auto bad = j(validDoc);
        bad.object["ipc"].array[0].object["allow"] = parseJSON(`[{"from":"Ghost","to":"System"}]`);
        cerrs = null; compile(bad, g, cerrs);
        check(cerrs.any!(e => e.message.canFind("unknown identit")), "ipc unknown from-identity reported");

        // keyBroker references unknown service → Stage 4
        auto bad2 = j(validDoc);
        bad2.object["ipc"].array[0].object["keyBroker"] = JSONValue("ghostd");
        cerrs = null; compile(bad2, g, cerrs);
        check(cerrs.any!(e => e.message.canFind("unknown service")), "ipc unknown keyBroker reported");
    }

    // ── Phase 8: generations build/switch/rollback/diff ──────────────────────
    writeln("[P8] generations store");
    {
        auto storeDir = tempDir() ~ "/anom-test-store";
        if (exists(storeDir)) { try { rmdirRecurse(storeDir); } catch (Exception) {} }
        auto s = openStore(storeDir);
        auto doc = j(validDoc);
        // build twice (identical) → dedups to same id
        auto id1 = buildGeneration(s, doc, "{}");
        auto id2 = buildGeneration(s, doc, "{}");
        check(id1 == id2, "identical config dedups to one generation");

        // switch updates current
        check(switchTo(s, id1), "switchTo succeeds");
        check(currentGen(s) == id1, "current points at switched gen");

        // a second distinct generation with a parent, then rollback
        auto doc2 = j(validDoc); doc2.object["system"].object["hostname"] = JSONValue("changed");
        auto id3 = buildGeneration(s, doc2, "{}", id1);
        check(id3 != id1, "distinct config → distinct generation");
        check(switchTo(s, id3), "switch to gen2");
        bool ok;
        auto rolled = rollback(s, ok);
        check(ok && rolled == id1, "rollback follows parent chain back to gen1");
        check(currentGen(s) == id1, "current repointed after rollback");

        // rollback with no parent (root) fails cleanly
        switchTo(s, id1);
        auto r2 = rollback(s, ok);
        check(!ok, "rollback from root (no parent) fails cleanly");

        // diff between two generations
        auto d = diffGenerations(s, id1, id3);
        check(d.any!(e => e.section == "system"), "diff detects changed system section");

        // list generations
        auto gens = listGenerations(s);
        check(gens.length >= 2, "listGenerations returns stored gens");

        // switch to missing gen fails
        check(!switchTo(s, "deadbeefdeadbeef"), "switch to missing gen fails");

        // corrupt meta.json → loadMeta returns empty parent (no crash)
        try { rmdirRecurse(storeDir); } catch (Exception) {}
    }

    // ── Phase 9: GUI identity colors ─────────────────────────────────────────
    writeln("[P9] GUI identity colors");
    {
        check(parseColor("#E02020") == 0xFFE02020, "#RRGGBB → opaque 0xFFRRGGBB");
        check(parseColor("#80E02020") == 0x80E02020, "#AARRGGBB → as-is");
        check(validColor("#ABCDEF"), "valid #RRGGBB accepted");
        check(validColor("#80ABCDEF"), "valid #AARRGGBB accepted");
        check(!validColor("blue"), "non-hex color rejected");
        check(!validColor("#12345"), "wrong-length color rejected");
    }

    // ── Phase 10: module/import system ───────────────────────────────────────
    writeln("[P10] module/import system");
    {
        auto tmp = tempDir() ~ "/anom-test-mods";
        if (exists(tmp)) { try { rmdirRecurse(tmp); } catch (Exception) {} }
        mkdirRecurse(tmp);
        std.file.write(tmp ~ "/base.json", `{"services":[{"name":"a","identity":"X","capabilities":["c"]}],
                                              "identities":[{"name":"X","rightsCeiling":"c","net":"none"}],
                                              "capabilities":{"c":{"rights":["read"]}}}`);
        std.file.write(tmp ~ "/more.json", `{"services":[{"name":"a","restart":"always"},
                                                        {"name":"b","identity":"X","capabilities":["c"]}]}`);
        std.file.write(tmp ~ "/top.json", `{"imports":["base.json","more.json"]}`);
        JSONValue merged; ModuleError merr;
        check(loadWithImports(tmp ~ "/top.json", merged, merr), "modules load+merge");
        // 'a' merged by name (has identity from base + restart from more); 'b' appended
        auto svcs = merged.object["services"].array;
        check(svcs.length == 2, format("name-keyed service merge (got %d)", svcs.length));
        bool aHasRestart;
        foreach (s; svcs) if (s.object["name"].str == "a" && "restart" in s.object) aHasRestart = true;
        check(aHasRestart, "service 'a' merged fields from both modules");
        check(!("imports" in merged.object), "imports key consumed and removed");
        // missing import file
        std.file.write(tmp ~ "/bad.json", `{"imports":["nope.json"]}`);
        check(!loadWithImports(tmp ~ "/bad.json", merged, merr) && merr.message.canFind("cannot read"),
              "missing import reported");
    }

    // ── Phase 11: live reconfiguration classification ────────────────────────
    writeln("[P11] live reconfiguration");
    {
        auto doc = j(validDoc);
        auto cls = classifyLive(doc);
        check(cls["gui"] == LiveClass.live, "gui = live");
        check(cls["logging"] == LiveClass.live, "logging = live");
        check(cls["ipc"] == LiveClass.live, "ipc = live");
        check(cls["kernel"] == LiveClass.reboot, "kernel = reboot");
        check(cls["boot"] == LiveClass.reboot, "boot = reboot");
        check(cls["system"] == LiveClass.reboot, "system/generation = reboot");
        check(cls["namespaces"] == LiveClass.reboot, "namespaces = reboot");
        check(cls["compatibility"] == LiveClass.reboot, "compatibility = reboot");
    }

    // ── Phase 12: integration (full pipeline + graph DOT + warnings) ──────────
    writeln("[P12] integration");
    {
        // the §2.3-style example compiles clean end-to-end
        auto doc = j(validDoc);
        CompiledGraph g; CompileError[] cerrs;
        auto ok = compile(doc, g, cerrs);
        check(ok && cerrs.length == 0, "integration: full pipeline clean");

        // graph_to_dot emits parseable DOT
        auto dot = graphToDot(g);
        check(dot.startsWith("digraph anonymos") && dot.canFind("}") &&
              dot.canFind("n1"), "graph emits DOT with nodes");

        // rootless=false → compile warning (§17)
        auto nr = j(validDoc);
        nr.object["security"].object["rootless"] = JSONValue(false);
        cerrs = null; compile(nr, g, cerrs);
        check(g.warnings.any!(w => w.canFind("rootless=false")), "rootless=false emits warning");

        // rejected config never partially applied: errors non-empty ⇒ compile false
        auto bad = j(validDoc);
        bad.object["services"].array[0].object["depends"] = parseJSON(`["ghost"]`);
        cerrs = null; ok = compile(bad, g, cerrs);
        check(!ok && cerrs.length > 0, "rejected config returns false with errors");

        // configHash is stable (canonical)
        auto h1 = configHashOf(doc);
        auto h2 = configHashOf(doc);
        check(h1 == h2 && h1.length == 64, "configHash stable 64-hex sha256");
    }

    // ── Phase 13: §4 manifest roundtrip (CompiledGraph → signed blob) ────────
    writeln("[P13] §4 manifest emission + HMAC");
    {
        import anonymos.config.manifest : buildManifest, manifestHmac,
            MANIFEST_MAGIC, MANIFEST_VERSION, MANIFEST_HEADER_SIZE, MANIFEST_HMAC_SIZE;
        auto doc = j(validDoc);
        CompiledGraph g; CompileError[] cerrs;
        compile(doc, g, cerrs);
        auto blob = buildManifest(g, doc);

        // header: magic, version, nonzero record count
        check(blob.length >= MANIFEST_HEADER_SIZE + MANIFEST_HMAC_SIZE, "blob >= header+hmac");
        check(blob[0] == 'A' && blob[1] == 'C' && blob[2] == 'F' && blob[3] == 'G',
              "magic ACGF");
        uint ver = blob[4] | (blob[5]<<8) | (blob[6]<<16) | (blob[7]<<24);
        check(ver == MANIFEST_VERSION, "manifest version");
        uint cnt = blob[8] | (blob[9]<<8) | (blob[10]<<16) | (blob[11]<<24);
        check(cnt > 0, "nonzero record count");

        // HMAC trailer verifies against the body (the kernel's cryptoVerify path)
        auto body = blob[0 .. $ - MANIFEST_HMAC_SIZE];
        auto embedded = blob[$ - MANIFEST_HMAC_SIZE .. $];
        auto recomputed = manifestHmac(body);
        bool hmacOk = true;
        foreach (i; 0 .. MANIFEST_HMAC_SIZE) if (recomputed[i] != embedded[i]) hmacOk = false;
        check(hmacOk, "HMAC trailer verifies (kernel will accept)");

        // a single-bit flip in the body breaks the HMAC (tamper detection)
        auto tampered = blob.dup;
        tampered[MANIFEST_HEADER_SIZE] ^= 1; // flip a bit in the first record
        auto tamperedBody = tampered[0 .. $ - MANIFEST_HMAC_SIZE];
        auto tamperedTag = manifestHmac(tamperedBody);
        bool tamperDetected = false;
        foreach (i; 0 .. MANIFEST_HMAC_SIZE) if (tamperedTag[i] != embedded[i]) tamperDetected = true;
        check(tamperDetected, "tampered manifest HMAC mismatch (kernel rejects)");

        // record walk: count + tag sanity (nsAlloc=4, identityCreate=3, svcReg=1...)
        size_t i = MANIFEST_HEADER_SIZE; const ulong bodyEnd = blob.length - MANIFEST_HMAC_SIZE;
        uint walked = 0;
        bool sawSvcReg, sawIdentityCreate, sawNsAlloc, sawSvcStartAll, sawIdentityFreeze;
        while (i + 2 <= bodyEnd && walked < cnt) {
            ubyte tag = blob[i]; ubyte len = blob[i+1];
            if (tag == 4) sawNsAlloc = true;
            if (tag == 3) sawIdentityCreate = true;
            if (tag == 1) sawSvcReg = true;
            if (tag == 6) sawIdentityFreeze = true;
            if (tag == 7) sawSvcStartAll = true;
            i += 2 + len; walked++;
        }
        check(walked == cnt, format("walked all %d records (got %d)", cnt, walked));
        check(sawNsAlloc && sawIdentityCreate && sawSvcReg && sawSvcStartAll,
              "manifest contains ns/identity/svc/start records");

        // deterministic: same doc → byte-identical blob
        auto blob2 = buildManifest(g, doc);
        check(blob == blob2, "manifest emission is deterministic");
    }

    writefln("\n[test] anonymos-config phases: %d/%d passed", pass, total);
    return pass == total ? 0 : 1;
}

// A valid, self-consistent document (subset of the spec §2.3 example) reused
// across phases.  Capabilities form a valid lattice; all references resolve.
// NB: a q"{}" token string would mis-match on the JSON's own braces, so use a
// delimited string q"DOC(...)DOC" instead.
enum validDoc = q"DOC
  {
  "system":  { "name": "x1", "hostname": "anon", "generation": 1 },
  "kernel":  { "features": ["smp"], "options": { "mem": "2G" } },
  "boot":    { "configPath": "/system.json", "measured": true },
  "security":{ "rootless": true, "immutableImage": true },
  "objects": { "root": { "_type": "Directory", "source": "bundle:/" } },
  "capabilities": {
    "fs-rw":   { "rights": ["read","write","stat"] },
    "fs-ro":   { "inherits": "fs-rw", "rights": ["read","stat"] },
    "call":    { "rights": ["call"] },
    "system-baseline": { "rights": ["read","write","stat","call"] }
  },
  "identities": [
    { "name": "System",   "color": "#2A2A2A", "trust": "system",
      "rightsCeiling": "system-baseline", "namespace": "system-ns", "net": "none" },
    { "name": "Personal", "color": "#3478F6", "trust": "personal",
      "rightsCeiling": "fs-rw", "namespace": "user-ns", "net": "nat", "clip": "same" },
    { "name": "Banking",  "color": "#E02020", "trust": "banking",
      "rightsCeiling": "fs-ro", "namespace": "bank-ns", "net": "vpn",
      "clip": "deny", "gui": ["borderAlways","noScreenshotAcrossId"] }
  ],
  "namespaces": [
    { "name": "system-ns", "root": "$root", "isolated": true },
    { "name": "user-ns",   "root": "$root", "inherits": "system-ns" },
    { "name": "bank-ns",   "root": "$root", "isolated": true }
  ],
  "services": [
    { "name": "init", "executable": "/init", "identity": "System",
      "capabilities": ["fs-rw"], "restart": "never" },
    { "name": "netd", "executable": "/sbin/netd", "identity": "System",
      "capabilities": ["call"], "depends": ["init"] }
  ],
  "ipc": [
    { "name": "secure", "dh": true, "keyBroker": "netd", "audit": true,
      "allow": [ { "from": "Personal", "to": "System", "broker": "netd" } ] }
  ],
  "storage": [
    { "name": "base", "kind": "immutable", "generation": "g1", "readOnly": true },
    { "name": "var",  "kind": "object-store", "source": "/var", "readOnly": false }
  ],
  "snapshots": [ { "name": "g1", "auto": true } ],
  "gui":      { "compositor": "mutter", "borderPolicy": "always", "defaultColor": "#2A2A2A" },
  "compatibility": { "linux": { "enabled": true, "personality": "x86_64" } },
  "logging":  { "level": "info", "audit": true, "sink": "/var/log/audit" },
  "networking":{ "hostname": "anon", "dns": ["10.0.0.1"] },
  "distributed": { "enabled": false }
  }
DOC";
