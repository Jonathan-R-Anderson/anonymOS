// validator.d — Phase 1 (Stage 2) of roadmap/DECLARITIVE_MODEL_ROADMAP.md,
// implementing the structural schema validator from DECLARATIVE_CONFIG_SPEC.md §3
// Stage 2.  It walks a parsed JSON document against schema.d's schema tree and
// collects ALL structural errors in one pass (§12 "fail once"), each carrying an
// exact JSON path so a user can fix every typo without re-running.
//
// Type mismatches, bad enums, malformed #RRGGBB colors, unknown top-level keys
// and missing required fields are reported here.  Reference *resolution* (does a
// named service exist?) is NOT this stage — that is Stage 4 in compiler.d, which
// consumes the refKind annotations the schema attaches to strings.
module anonymos.config.validator;

import anonymos.config.schema;
import std.json;
import std.array;
import std.format;
import std.ascii;

// A structural validation problem with an exact JSON path.
struct ValidationError
{
    string path;   // e.g. "identities[2].color"
    string message;
    string toString() const { return format("%s: %s", path, message); }
}

// The result of parsing raw text: either a document or a single fatal parse
// error with the byte offset (Stage 1).  std.json gives us the offset via its
// JSONException location when available.
struct ParseResult
{
    bool ok;
    JSONValue doc;
    string error;
    size_t offset; // byte offset of a malformed-JSON error, when known
}

// Stage 1: JSON decode.  Malformed JSON is a single fatal error.
ParseResult parseText(string text)
{
    ParseResult r;
    try
    {
        r.doc = parseJSON(text);
        r.ok = true;
    }
    catch (JSONException e)
    {
        r.ok = false;
        r.error = e.msg;
        // std.json's message embeds the offset as " (N)" in some builds; expose
        // it best-effort.  We don't depend on the exact wording.
        r.offset = size_t.max;
    }
    return r;
}

// Stage 2: structural validation against the schema.  Returns every error found
// (collect-all), never stops at the first.
ValidationError[] validate(const ref JSONValue doc)
{
    ValidationError[] errors;
    auto root = documentSchema();
    walk(doc, root, "", errors);
    return errors;
}

private:

void record(ref ValidationError[] errors, string path, string msg)
{
    ValidationError e;
    e.path = path;
    e.message = msg;
    errors ~= e;
}

void walk(const ref JSONValue v, const ref SchemaNode n, string path,
          ref ValidationError[] errors)
{
    final switch (n.kind)
    {
    case SchemaKind.objectK:
        if (v.type != JSONType.object)
        {
            record(errors, path, format("expected object, got %s", jsonTypeName(v)));
            return;
        }
        // required fields present?
        foreach (k, child; n.props)
            if (child.required && !(k in v.object))
                record(errors, path.length ? path ~ "." ~ k : k, "missing required field");
        // each present key: known + recursively valid; unknown keys rejected
        // unless allowUnknownKeys (free-form sections).
        foreach (k, val; v.object)
        {
            string childPath = path.length ? path ~ "." ~ k : k;
            if (auto p = k in n.props)
            {
                walk(val, *p, childPath, errors);
            }
            else if (!n.allowUnknownKeys)
            {
                record(errors, childPath, "unknown field");
            }
            // free-form: accept any value, descend no further
        }
        break;
    case SchemaKind.arrayK:
        if (v.type != JSONType.array)
        {
            record(errors, path, format("expected array, got %s", jsonTypeName(v)));
            return;
        }
        if (!n.items) break;
        foreach (i, elem; v.array)
            walk(elem, *n.items, format("%s[%d]", path, i), errors);
        break;
    case SchemaKind.stringK:
        if (v.type != JSONType.string)
            record(errors, path, format("expected string, got %s", jsonTypeName(v)));
        break;
    case SchemaKind.enumK:
        if (v.type != JSONType.string)
        {
            record(errors, path, format("expected one of %s, got %s",
                                        n.enumVals, jsonTypeName(v)));
            return;
        }
        bool found = false;
        foreach (ev; n.enumVals)
            if (v.str == ev) { found = true; break; }
        if (!found)
            record(errors, path, format("'%s' is not one of %s", v.str, n.enumVals));
        break;
    case SchemaKind.intK:
        if (v.type != JSONType.integer)
            record(errors, path, format("expected integer, got %s", jsonTypeName(v)));
        break;
    case SchemaKind.boolK:
        if (v.type != JSONType.true_ && v.type != JSONType.false_)
            record(errors, path, format("expected boolean, got %s", jsonTypeName(v)));
        break;
    case SchemaKind.colorK:
        if (v.type != JSONType.string)
        {
            record(errors, path, format("expected color string, got %s", jsonTypeName(v)));
            return;
        }
        if (!validColor(v.str))
            record(errors, path, format("'%s' is not a valid #RRGGBB or #AARRGGBB color", v.str));
        break;
    case SchemaKind.refK:
        if (v.type != JSONType.string)
            record(errors, path, format("expected reference string, got %s", jsonTypeName(v)));
        // existence is checked in Stage 4 (compiler.d), not here.
        break;
    case SchemaKind.freeK:
        break; // accept anything
    }
}

string jsonTypeName(const ref JSONValue v)
{
    switch (v.type)
    {
    case JSONType.object: return "object";
    case JSONType.array: return "array";
    case JSONType.string: return "string";
    case JSONType.integer: return "integer";
    case JSONType.float_: return "float";
    case JSONType.true_: return "boolean";
    case JSONType.false_: return "boolean";
    case JSONType.null_: return "null";
    default: return "unknown";
    }
}

// #RRGGBB (6 hex) or #AARRGGBB (8 hex), case-insensitive.
// #RRGGBB (6 hex) or #AARRGGBB (8 hex), case-insensitive.  Public so the test
// suite (and any host tool) can reuse the same color-validity rule.
public bool validColor(string s)
{
    if (s.length != 7 && s.length != 9) return false;
    if (s[0] != '#') return false;
    foreach (i, c; s[1 .. $])
        if (!isHexDigit(c)) return false;
    return true;
}
