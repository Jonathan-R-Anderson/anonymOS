// generations.d — Phase 8 (§10, §14 build/switch/rollback) of the compiler.
// Implements the config-side generation store: a config change creates a NEW
// generation whose content is the canonical JSON, content-addressed by
// configHash = sha256(canonical_json).  Previous generations stay bootable;
// switch atomically repoints `current`; rollback follows the `parent` chain.
//
// Store layout (spec §3 data structures / Phase 8):
//   <store>/gens/<id>/{system.json, manifest.json, meta.json}
//   <store>/current            (symlink → gens/<id>)
//   <store>/journal.log        (append-only: build/switch/rollback events)
//
// This is the host-side analogue of core/store.d's genCreate/genSetActive/
// genRollback: the kernel's generations snapshot the *system tree*, these
// snapshot the *config document* and select which system generation to boot.
module anonymos.config.generations;

import std.json;
import std.file;
import std.path;
import std.format;
import std.digest.sha;
import std.array;
import std.algorithm;
import std.conv;
import std.stdio : File;
import std.datetime.systime : Clock, SysTime;

private long nowEpoch() { return Clock.currTime.toUnixTime(); }

// Metadata for one stored generation (spec Phase 8 data structure).
struct GenerationMeta
{
    string id;         // configHash short form (first 16 hex chars)
    long created;      // unix epoch seconds
    string parent;     // parent generation id ("" = root)
    string configHash; // full sha256 hex
    bool live;         // is this the current/active generation
}

struct GenerationStore
{
    string root; // directory holding gens/, current, journal.log
}

GenerationStore openStore(string root)
{
    GenerationStore s;
    s.root = root;
    try { mkdirRecurse(root); } catch (Exception) {}
    return s;
}

// Canonical JSON text: std.json toJSON with pretty=false = no extra whitespace;
// std.json sorts object keys on serialization, so identical configs yield
// byte-identical text (§17 reproducibility).
string canonicalJson(const ref JSONValue v)
{
    return toJSON(v, false);
}

string configHashOf(const ref JSONValue v)
{
    auto canon = canonicalJson(v);
    auto digest = sha256Of(canon);
    return toHex(digest[]);
}

string shortHash(string fullHex) { return fullHex.length >= 16 ? fullHex[0 .. 16] : fullHex; }

private string toHex(const(ubyte)[] d)
{
    string s;
    foreach (b; d) s ~= format("%02x", b);
    return s;
}

// Build a new generation from a resolved+compiled config.  Writes system.json
// (canonical), manifest.json (the compiled graph), meta.json.  Dedups: an
// identical config reuses the existing generation id.  Returns the id.
string buildGeneration(const ref GenerationStore s, const ref JSONValue doc,
                       string manifestJson, string parent = "")
{
    auto full = configHashOf(doc);
    auto id = shortHash(full);
    auto genDir = buildNormalizedPath(s.root ~ "/gens/" ~ id);
    if (!exists(genDir))
    {
        mkdirRecurse(genDir);
        std.file.write(buildNormalizedPath(genDir ~ "/system.json"), canonicalJson(doc));
        std.file.write(buildNormalizedPath(genDir ~ "/manifest.json"), manifestJson);
        auto m = metaRecord(id, full, parent);
        auto mj = metaToJson(m);
        std.file.write(buildNormalizedPath(genDir ~ "/meta.json"), toJSON(mj, false));
    }
    appendJournal(s, format("build %s parent=%s", id, parent));
    return id;
}

private GenerationMeta metaRecord(string id, string fullHash, string parent)
{
    GenerationMeta m;
    m.id = id;
    m.created = nowEpoch();
    m.parent = parent;
    m.configHash = fullHash;
    m.live = false;
    return m;
}

JSONValue metaToJson(const ref GenerationMeta m)
{
    auto o = JSONValue(string[string].init);
    o.object["id"] = JSONValue(m.id);
    o.object["created"] = JSONValue(m.created);
    o.object["parent"] = JSONValue(m.parent);
    o.object["configHash"] = JSONValue(m.configHash);
    o.object["live"] = JSONValue(m.live);
    return o;
}

// Atomically set the active generation by repointing the `current` symlink.
bool switchTo(const ref GenerationStore s, string id)
{
    auto genDir = buildNormalizedPath(s.root ~ "/gens/" ~ id);
    if (!exists(genDir)) { appendJournal(s, format("switch %s FAILED (missing)", id)); return false; }
    auto cur = buildNormalizedPath(s.root ~ "/current");
    // Remove any prior current entry (file OR symlink, even a dangling one).
    // exists() returns false for a dangling symlink and isSymlink() throws on a
    // missing path, so guard both with a try.
    try { if (exists(cur) || isSymlink(cur)) remove(cur); } catch (Exception) {}
    symlink("gens/" ~ id, cur);
    bumpLive(s, id);
    appendJournal(s, format("switch %s", id));
    return true;
}

// Roll back to the parent of the currently-active generation.
string rollback(const ref GenerationStore s, out bool ok)
{
    ok = false;
    auto cur = currentGen(s);
    if (!cur.length) { appendJournal(s, "rollback FAILED (no current)"); return ""; }
    auto m = loadMeta(s, cur);
    if (!m.parent.length)
    {
        appendJournal(s, format("rollback %s FAILED (no parent)", cur));
        return "";
    }
    ok = switchTo(s, m.parent);
    appendJournal(s, format("rollback %s -> %s", cur, m.parent));
    return m.parent;
}

string currentGen(const ref GenerationStore s)
{
    auto cur = buildNormalizedPath(s.root ~ "/current");
    try
    {
        auto target = readLink(cur);
        if (target.startsWith("gens/")) return target[5 .. $];
        return baseName(target);
    }
    catch (Exception) { return ""; }
}

GenerationMeta loadMeta(const ref GenerationStore s, string id)
{
    GenerationMeta m;
    auto p = buildNormalizedPath(s.root ~ "/gens/" ~ id ~ "/meta.json");
    try
    {
        auto doc = parseJSON(readText(p));
        if ("id" in doc.object) m.id = doc.object["id"].str;
        if ("created" in doc.object) m.created = doc.object["created"].integer;
        if ("parent" in doc.object) m.parent = doc.object["parent"].str;
        if ("configHash" in doc.object) m.configHash = doc.object["configHash"].str;
        if ("live" in doc.object) m.live = doc.object["live"].boolean;
    }
    catch (Exception) {}
    return m;
}

GenerationMeta[] listGenerations(const ref GenerationStore s)
{
    GenerationMeta[] out_;
    auto gensDir = buildNormalizedPath(s.root ~ "/gens");
    if (!exists(gensDir)) return out_;
    string cur = currentGen(s);
    try
    {
        foreach (de; dirEntries(gensDir, SpanMode.shallow, false))
        {
            if (!de.isDir) continue;
            auto m = loadMeta(s, baseName(de.name));
            m.live = (m.id == cur);
            out_ ~= m;
        }
    }
    catch (Exception) {}
    out_.sort!((a, b) => a.id < b.id);
    return out_;
}

// Structured diff between two generations: which top-level sections changed,
// each labelled live/reboot (so the user knows if a switch needs a reboot).
struct GenDiffEntry { string section; string klass; string change; }

GenDiffEntry[] diffGenerations(const ref GenerationStore s, string a, string b)
{
    GenDiffEntry[] out_;
    auto ja = loadSectionKeys(s, a);
    auto jb = loadSectionKeys(s, b);
    auto keys = appender!(string[]);
    foreach (k, _; ja) keys ~= k;
    foreach (k, _; jb) if (k !in ja) keys ~= k;
    keys.data.sort();
    foreach (k; keys.data)
    {
        string va = (k in ja) ? ja[k] : "";
        string vb = (k in jb) ? jb[k] : "";
        if (va != vb)
        {
            GenDiffEntry e;
            e.section = k;
            e.klass = liveOrReboot(k);
            e.change = va == "" ? "added" : (vb == "" ? "removed" : "changed");
            out_ ~= e;
        }
    }
    return out_;
}

private string[string] loadSectionKeys(const ref GenerationStore s, string id)
{
    string[string] r;
    auto p = buildNormalizedPath(s.root ~ "/gens/" ~ id ~ "/system.json");
    try
    {
        auto doc = parseJSON(readText(p));
        if (doc.type == JSONType.object)
            foreach (k, v; doc.object)
                r[k] = toJSON(v, false);
    }
    catch (Exception) {}
    return r;
}

private string liveOrReboot(string section)
{
    foreach (live; ["gui", "logging", "ipc", "networking", "services", "security"])
        if (section == live) return "live";
    return "reboot";
}

private void appendJournal(const ref GenerationStore s, string line)
{
    auto p = buildNormalizedPath(s.root ~ "/journal.log");
    auto ts = nowEpoch();
    try
    {
        auto f = File(p, "a");
        f.writefln("[%s] %s", ts, line);
        f.close();
    }
    catch (Exception) {}
}

private void bumpLive(const ref GenerationStore s, string id)
{
    auto m = loadMeta(s, id);
    if (!m.live)
    {
        m.live = true;
        auto j = metaToJson(m);
        std.file.write(buildNormalizedPath(s.root ~ "/gens/" ~ id ~ "/meta.json"),
                       toJSON(j, false));
    }
}
