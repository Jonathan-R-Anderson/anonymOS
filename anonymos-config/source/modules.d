// modules.d — Phase 10 (Stage 3) of the declarative-config compiler.
// Implements the module/import system from DECLARATIVE_CONFIG_SPEC.md §11:
// avoid one giant JSON file by importing base.json, hardware.json, etc.
//
// Merge semantics (spec §11):
//   - deep-merge left-to-right; later imports win on scalar conflict;
//   - arrays of {name}-keyed objects merge BY NAME (two modules can each
//     contribute services without clobbering); other arrays concatenate;
//   - the file's own body wins over its imports;
//   - `imports` is consumed and removed from the merged output;
//   - import cycles (a module importing itself transitively) are detected via
//     the resolution stack and rejected.
// The final build still compiles into ONE canonical resolved JSON graph.
module anonymos.config.modules;

import std.json;
import std.array;
import std.file;
import std.path;
import std.algorithm;

// A problem loading/merging modules (distinct from a structural ValidationError;
// these are fatal — a module cycle or a missing file aborts before validation).
struct ModuleError
{
    string file;
    string message;
    string toString() const { return format("%s: %s", file, message); }
}

import std.format;

// Load a config file, recursively resolving its `imports[]` against the same
// directory, deep-merging into one document with the file's own body on top.
// Returns false + fills `err` on a missing file, malformed JSON, or an import
// cycle.  The returned document has no `imports` key.
bool loadWithImports(string path, out JSONValue merged, out ModuleError err)
{
    string[] stack; // absolute paths currently being resolved (cycle guard)
    JSONValue body;
    if (!loadAndMerge(path, stack, body, err)) return false;
    // consume + remove imports from the final merged document
    if ("imports" in body.object) body.object.remove("imports");
    merged = body;
    return true;
}

private bool loadAndMerge(string path, ref string[] stack, out JSONValue body,
                          out ModuleError err)
{
    string abs;
    try abs = absolutePath(path);
    catch (Exception)
    {
        err.file = path;
        err.message = "cannot resolve path";
        return false;
    }
    // cycle detection
    foreach (s; stack)
        if (s == abs)
        {
            err.file = abs;
            err.message = "import cycle detected (module imports itself transitively)";
            return false;
        }

    string text;
    try text = readText(path);
    catch (FileException e)
    {
        err.file = path;
        err.message = "cannot read file: " ~ e.msg;
        return false;
    }

    JSONValue doc;
    try doc = parseJSON(text);
    catch (JSONException e)
    {
        err.file = path;
        err.message = "malformed JSON: " ~ e.msg;
        return false;
    }
    if (doc.type != JSONType.object)
    {
        err.file = path;
        err.message = "top level must be an object";
        return false;
    }

    stack ~= abs;
    scope (success) stack = stack[0 .. $ - 1];

    // Start from this file's own body (minus imports), then fold in imports
    // underneath: imports first (left→right), then this body on top wins.
    auto dir = dirName(path);
    JSONValue[] imported;
    if (auto imp = "imports" in doc.object)
    {
        if (imp.type != JSONType.array)
        {
            err.file = path;
            err.message = "imports must be an array of strings";
            return false;
        }
        foreach (m; imp.array)
        {
            if (m.type != JSONType.string)
            {
                err.file = path;
                err.message = "imports entries must be strings";
                return false;
            }
            JSONValue merged;
            string mpath = buildNormalizedPath(dir ~ "/" ~ m.str);
            if (!loadAndMerge(mpath, stack, merged, err)) return false;
            imported ~= merged;
        }
    }

    // merged = foldl(deepMerge, imported[0], imported[1..]) then deepMerge(self)
    if (imported.length == 0)
    {
        body = doc;
    }
    else
    {
        body = imported[0];
        foreach (m; imported[1 .. $]) body = deepMerge(body, m);
        body = deepMerge(body, doc); // this file wins over its imports
    }
    return true;
}

// Deep merge: b wins on scalar conflict (call order merge(base, override)).
// Arrays of objects sharing a "name" key merge element-by-element by name;
// all other arrays concatenate.  Returns a new value.  Value params: each
// JSONValue is copied (a tagged union), so the inputs are not mutated and the
// result is independently mutable.
JSONValue deepMerge(JSONValue a, JSONValue b)
{
    if (a.type != JSONType.object || b.type != JSONType.object) return b;
    JSONValue r = a; // shallow copy of a's object map
    foreach (k, bv; b.object)
    {
        if (auto av = k in r.object)
            r.object[k] = mergeValue(*av, bv);
        else
            r.object[k] = bv;
    }
    return r;
}

private JSONValue mergeValue(JSONValue a, JSONValue b)
{
    if (a.type == JSONType.object && b.type == JSONType.object)
        return deepMerge(a, b);
    if (a.type == JSONType.array && b.type == JSONType.array)
        return mergeNamedArrays(a.array.dup, b.array.dup);
    return b; // scalar: b wins
}

// If every element of BOTH arrays is an object carrying a "name" key, merge
// by name (a's entry updated/extended by b's matching entry, b-only entries
// appended).  Otherwise concatenate a ++ b.
private JSONValue mergeNamedArrays(JSONValue[] a, JSONValue[] b)
{
    bool allNamed(JSONValue[] arr)
    {
        foreach (e; arr)
            if (e.type != JSONType.object || "name" !in e.object ||
                e.object["name"].type != JSONType.string)
                return false;
        return true;
    }
    if (!allNamed(a) || !allNamed(b))
    {
        JSONValue cat;
        cat.array = a ~ b;
        return cat;
    }
    // merge by name, preserving a's order, appending b-only names after
    JSONValue[string] byName;
    string[] order;
    foreach (e; a)
    {
        string nm = e.object["name"].str;
        if (nm !in byName) order ~= nm;
        byName[nm] = e;
    }
    foreach (e; b)
    {
        string nm = e.object["name"].str;
        if (auto ex = nm in byName)
            byName[nm] = deepMerge(*ex, e);
        else { byName[nm] = e; order ~= nm; }
    }
    // Initialize r as an array before appending (accessing .array on a
    // default/null JSONValue throws "not an array").
    JSONValue r = JSONValue(string[].init);
    foreach (nm; order) r.array ~= byName[nm];
    return r;
}
