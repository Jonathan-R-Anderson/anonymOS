// The operating system's objects as dash values.  Each object type has fields (read from the
// kernel's live views: /objects/<kind>/<name>/meta and the /config/*.json documents) and methods
// (actions through /config/domain.action and the native object ABI).  Every type registers its
// members, so Tab completion and :m can show them before you have an instance.
module dash.objects;

import dash.rt;
import dash.value;
import dash.eval;
import dash.json;
import dash.lib : readWholeFile;
import dash.exec;

enum long HOS_SYS_QUERY = 0x4000;
enum long HOSQ_OBJECTS = 1, HOSQ_IDENTITIES = 2, HOSQ_NAMESPACES = 3, HOSQ_SERVICES = 4, HOSQ_SYS = 5,
          HOSQ_WHOAMI = 6, HOSQ_CAP_GRANT = 20, HOSQ_NS_CLONE = 21, HOSQ_NS_ENTER = 22, HOSQ_ID_SWITCH = 23;

// B5: destructive operations -- `dry-run` reports, `arm` authorises exactly the next one.
__gshared bool g_dryRun, g_armed;

@nogc nothrow:

// ── the native object ABI ───────────────────────────────────────────────────────────────────────
extern (C) int* __errno_location();
int errnoNow() { return *__errno_location(); }
private __gshared char[16384] g_q = 0;
bool nativeAvailable() {
    const r = syscall(HOS_SYS_QUERY, HOSQ_WHOAMI, 0, cast(long)g_q.ptr, g_q.length - 1);
    return r >= 0;
}
// A text query; null (with an error) when this process has no native authority.
const(char)[] query(long op) {
    const n = syscall(HOS_SYS_QUERY, op, 0, cast(long)g_q.ptr, g_q.length - 1);
    if (n < 0) {
        setErr(errnoNow() == 38 ? "the native object ABI is not available here (dash is not running as the native shell, or this is a Linux shell)"
                        : "native query failed");
        return null;
    }
    g_q[cast(size_t)n] = 0;
    return g_q[0 .. cast(size_t)n];
}

// ── helpers ─────────────────────────────────────────────────────────────────────────────────────
Value* kvValue(const(char)[] v) {
    if (v == "true") return g_true;
    if (v == "false") return g_false;
    if (v.length && (isDigit(v[0]) || (v[0] == '-' && v.length > 1 && isDigit(v[1])))) {
        auto z = cz(v); char* e; const x = strtoll(z, &e, 0); const ok = *e == 0; free(z);
        if (ok) return mkInt(x);
    }
    return mkStr(v);
}
// "key=value" lines -> fields of r (comments and blank lines skipped)
Value* parseKV(Value* r, const(char)[] text) {
    size_t st = 0;
    foreach (k; 0 .. text.length + 1) {
        if (k == text.length || text[k] == '\n') {
            auto line = text[st .. k];
            st = k + 1;
            if (line.length == 0 || line[0] == '#') continue;
            size_t eq = line.length;
            foreach (q, c; line) if (c == '=') { eq = q; break; }
            if (eq == line.length) continue;
            auto key = line[0 .. eq];
            if (key == "type") continue;                  // the object's type is the value's type
            r = withField(r, intern(key), kvValue(line[eq + 1 .. $]));
        }
    }
    return r;
}
private Value* readQuiet(const(char)[] path) {
    auto z = cz(path);
    const fd = open(z, O_RDONLY); free(z);
    if (fd < 0) return null;
    Buf b; char[4096] t;
    for (;;) { const r = read(fd, t.ptr, t.length); if (r <= 0) break; b.put(t[0 .. cast(size_t)r]); }
    close(fd);
    auto v = mkStr(b.str()); b.dispose();
    return v;
}
// Names under a directory (sorted).
Value* dirNames(const(char)[] path) {
    auto z = cz(path); auto d = opendir(z); free(z);
    ListB lb;
    if (d is null) return lb.done();
    for (;;) {
        auto e = cast(Dirent*)readdir(d); if (e is null) break;
        const n = e.d_name.ptr[0 .. strlen(e.d_name.ptr)];
        if (n == "." || n == "..") continue;
        lb.push(mkStr(n));
    }
    closedir(d);
    // insertion sort (small lists)
    auto l = lb.done();
    foreach (k; 1 .. l.n) { auto x = l.items[k]; size_t j = k; while (j > 0 && valCmp(l.items[j - 1], x) > 0) { l.items[j] = l.items[j - 1]; --j; } l.items[j] = x; }
    return l;
}
private Value* jsonDoc(const(char)[] path) {
    auto t = readQuiet(path);
    if (!t) return null;
    auto v = parseJson(str(t));
    if (!v) clearErr();
    return v;
}
private Value* asObj(Value* rec, const(char)[] type) {
    auto o = mkObj(intern(type), rec.n);
    foreach (k; 0 .. rec.n) { o.keys[k] = rec.keys[k]; o.items[k] = rec.items[k]; }
    return o;
}

// An object of a /objects kind, by name: its meta fields, merged with its /config row (if any).
Value* loadObject(const(char)[] kind, const(char)[] type, const(char)[] name, Value* rows) {
    Buf p; p.put("/objects/"); p.put(kind); p.put('/'); p.put(name); p.put("/meta");
    auto meta = readQuiet(p.str()); p.dispose();
    auto o = mkObj(intern(type), 0);
    o = withField(o, intern("name"), mkStr(name));
    if (meta) o = parseKV(o, str(meta));
    if (rows && rows.t == VT.List) {
        foreach (k; 0 .. rows.n) {
            auto row = rows.items[k];
            auto nm = fieldS(row, "name");
            if (nm && nm.t == VT.Str && str(nm) == name) {
                foreach (j; 0 .. row.n) if (!field(o, row.keys[j])) o = withField(o, row.keys[j], row.items[j]);
                break;
            }
        }
    }
    o.name = intern(type); o.t = VT.Obj;
    return o;
}
Value* loadAll(const(char)[] kind, const(char)[] type, const(char)[] cfg) {
    Buf p; p.put("/objects/"); p.put(kind);
    auto pz = cz(p.str()); const viewable = access(pz, F_OK) == 0; free(pz);
    auto names = dirNames(p.str()); p.dispose();
    auto rows = cfg ? jsonDoc(cfg) : null;
    // Neither view is in this domain's namespace: say so, rather than an empty list that reads
    // as "there are none".  (Only the System domain is handed every domain's view.)
    if (!viewable && !rows)
        return err(kind, ": not visible from this domain -- its namespace has no /objects/", kind,
                   cfg.length ? " or " : "", cfg, " (the System domain sees them all)");
    if (names.n == 0 && rows && rows.t == VT.List) {           // no /objects view: the config rows alone
        auto r = mkList(rows.n);
        foreach (k; 0 .. rows.n) r.items[k] = asObj(rows.items[k], type);
        return r;
    }
    auto r = mkList(names.n);
    foreach (k; 0 .. names.n) r.items[k] = loadObject(kind, type, str(names.items[k]), rows);
    return r;
}
private Value* byName(Value* list, Value* name, const(char)[] what) {
    if (name.t != VT.Str) return err(what, ": expected a name (a String)");
    foreach (k; 0 .. list.n) { auto n = fieldS(list.items[k], "name"); if (n && valEq(n, name)) return list.items[k]; }
    Buf b; b.put("no "); b.put(what); b.put(" called \""); b.put(str(name)); b.put("\" (there are: ");
    foreach (k; 0 .. list.n) { if (k) b.put(", "); auto n = fieldS(list.items[k], "name"); if (n) textOf(b, n); }
    b.put(")");
    auto r = err(b.str());
    b.dispose();
    return r;
}

private const(char)[] nameOf(Value* o) { auto n = fieldS(o, "name"); return (n && n.t == VT.Str) ? str(n) : ""; }

// Write a domain control command ("verb Domain [arg]"); the kernel answers with the write's result.
Value* domainAction(const(char)[] verb, const(char)[] dom, const(char)[] arg) {
    if (g_pure) return err("(", verb, " has effects: not run while completing)", null);
    Buf cmd; cmd.put(verb); cmd.put(' '); cmd.put(dom); if (arg.length) { cmd.put(' '); cmd.put(arg); } cmd.put('\n');
    if (g_dryRun) { out_("dry-run: would send `"); out_(cmd.str()[0 .. cmd.n - 1]); out_("` to the Domain Manager\n"); cmd.dispose(); return g_unit; }
    const fd = open("/config/domain.action", O_WRONLY);
    if (fd < 0) { cmd.dispose(); return err("cannot reach the Domain Manager control file (/config/domain.action)"); }
    const w = write(fd, cmd.p, cmd.n);
    close(fd);
    cmd.dispose();
    if (w < 0) {
        const e = errnoNow();
        const(char)[] why = e == 1 ? "not permitted (only System may do that)" : e == 13 ? "access denied" : e == 16 ? "busy" :
                            e == 2 ? "no such domain" : e == 22 ? "invalid argument" : e == 6 ? "no such device" : "refused";
        return err(verb, " ", dom, ": ", why);
    }
    return g_unit;
}
private bool guard(const(char)[] verb) {
    if (g_dryRun) return true;          // domainAction reports
    if (!g_armed) { setErr(verb, " changes the system's security context: run `arm` first (or `dry-run` to see what it would do)"); return false; }
    g_armed = false;
    return true;
}

// ── collections ─────────────────────────────────────────────────────────────────────────────────
private Value* c_domains(Value** a, void* c) { return loadAll("domains", "Domain", "/config/domains.json"); }
private Value* c_identities(Value** a, void* c) { return loadAll("identities", "Identity", "/config/identities.json"); }
private Value* c_services(Value** a, void* c) { return loadAll("services", "Service", "/config/services.json"); }
private Value* c_users(Value** a, void* c) { return loadAll("users", "User", "/config/users.json"); }
private Value* c_namespaces(Value** a, void* c) {
    auto names = dirNames("/objects/namespaces");
    auto r = mkList(names.n);
    foreach (k; 0 .. names.n) {
        auto o = loadObject("namespaces", "Namespace", str(names.items[k]), null);
        r.items[k] = o;
    }
    return r;
}
private Value* c_domain(Value** a, void* c) { return byName(c_domains(null, null), a[0], "domain"); }
private Value* c_identity(Value** a, void* c) { return byName(c_identities(null, null), a[0], "identity"); }
private Value* c_service(Value** a, void* c) { return byName(c_services(null, null), a[0], "service"); }
private Value* c_user(Value** a, void* c) { return byName(c_users(null, null), a[0], "user"); }

private Value* c_objects(Value** a, void* c) {
    auto t = query(HOSQ_OBJECTS); if (!t) return null;
    ListB lb;
    size_t st = 0;
    foreach (k; 0 .. t.length + 1) {
        if (k == t.length || t[k] == '\n') {
            auto line = t[st .. k]; st = k + 1;
            size_t a0 = 0; while (a0 < line.length && isSpace(line[a0])) ++a0;
            size_t a1 = a0; while (a1 < line.length && !isSpace(line[a1])) ++a1;
            size_t b0 = a1; while (b0 < line.length && isSpace(line[b0])) ++b0;
            if (a1 == a0 || b0 >= line.length || !isDigit(line[b0])) continue;
            auto o = mkObj(intern("ObjCount"), 2);
            o.keys[0] = intern("type"); o.items[0] = mkStr(line[a0 .. a1]);
            o.keys[1] = intern("count"); o.items[1] = kvValue(line[b0 .. $]);
            lb.push(o);
        }
    }
    return lb.done();
}
private Value* c_me(Value** a, void* c) {
    auto t = query(HOSQ_WHOAMI); if (!t) return null;
    // "user@namespace [rights]"
    size_t at = t.length, sp = t.length;
    foreach (k, ch; t) { if (ch == '@' && at == t.length) at = k; if (ch == ' ' && sp == t.length) sp = k; }
    auto o = mkObj(intern("Me"), 0);
    o = withField(o, intern("user"), mkStr(t[0 .. at < t.length ? at : t.length]));
    o = withField(o, intern("namespace"), mkStr(at < t.length ? t[at + 1 .. (sp > at ? sp : t.length)] : ""));
    o = withField(o, intern("rights"), mkStr(sp < t.length ? t[sp + 1 .. $] : ""));
    // the domain this shell runs in: the terminal says, else it is the namespace
    auto d = getenv("EPIN_DOMAIN");
    o = withField(o, intern("domain"), (d && *d) ? mkStr(d[0 .. strlen(d)]) : fieldS(o, "namespace"));
    o.t = VT.Obj; o.name = intern("Me");
    return o;
}
private Value* c_system(Value** a, void* c) {
    auto o = mkObj(intern("System"), 0);
    auto t = query(HOSQ_SYS);
    if (t) { size_t e = t.length; while (e && t[e - 1] == '\n') --e; o = withField(o, intern("summary"), mkStr(t[0 .. e])); }
    else clearErr();
    auto doc = jsonDoc("/config/system.json");
    if (doc && (doc.t == VT.Record)) foreach (k; 0 .. doc.n) o = withField(o, doc.keys[k], doc.items[k]);
    o.t = VT.Obj; o.name = intern("System");
    return o;
}
private Value* c_apps(Value** a, void* c) {
    auto rows = jsonDoc("/config/apps.json");
    if (!rows || rows.t != VT.List) return err("cannot read /config/apps.json");
    auto r = mkList(rows.n);
    foreach (k; 0 .. rows.n) {
        auto o = asObj(rows.items[k], "App");
        auto id = fieldS(o, "id");
        if (id) o = withField(o, intern("name"), id);
        o.t = VT.Obj; o.name = intern("App");
        r.items[k] = o;
    }
    return r;
}
private Value* c_app(Value** a, void* c) { return byName(c_apps(null, null), a[0], "application"); }
private Value* c_usb(Value** a, void* c) {
    auto rows = jsonDoc("/config/usb.json");
    if (!rows || rows.t != VT.List) return err("cannot read /config/usb.json");
    auto r = mkList(rows.n);
    foreach (k; 0 .. rows.n) r.items[k] = asObj(rows.items[k], "UsbDevice");
    return r;
}
private Value* c_vnet(Value** a, void* c) { auto v = jsonDoc("/config/vnet.json"); return v ? v : err("cannot read /config/vnet.json"); }
private Value* c_procs(Value** a, void* c) {
    auto pids = dirNames("/proc");
    ListB lb;
    foreach (k; 0 .. pids.n) {
        auto n = str(pids.items[k]);
        bool num = n.length > 0; foreach (ch; n) if (!isDigit(ch)) num = false;
        if (!num) continue;
        Buf p; p.put("/proc/"); p.put(n); p.put("/status");
        auto st = readQuiet(p.str()); p.dispose();
        auto o = mkObj(intern("Process"), 0);
        o = withField(o, intern("pid"), kvValue(n));
        if (st) {
            // "Key:\tvalue" lines
            auto t = str(st); size_t s0 = 0;
            foreach (q; 0 .. t.length + 1) {
                if (q == t.length || t[q] == '\n') {
                    auto line = t[s0 .. q]; s0 = q + 1;
                    size_t col = line.length; foreach (w, ch; line) if (ch == ':') { col = w; break; }
                    if (col == line.length) continue;
                    auto key = line[0 .. col];
                    size_t v0 = col + 1; while (v0 < line.length && isSpace(line[v0])) ++v0;
                    auto val = line[v0 .. $];
                    if (key == "Name") o = withField(o, intern("name"), mkStr(val));
                    else if (key == "State") o = withField(o, intern("state"), mkStr(val));
                    else if (key == "PPid") o = withField(o, intern("ppid"), kvValue(val));
                    else if (key == "VmRSS") { size_t e = 0; while (e < val.length && isDigit(val[e])) ++e; o = withField(o, intern("rssKb"), kvValue(val[0 .. e])); }
                }
            }
        }
        o.t = VT.Obj; o.name = intern("Process");
        lb.push(o);
    }
    return lb.done();
}

// ── methods ─────────────────────────────────────────────────────────────────────────────────────
private Value* fieldFile(Value* o, const(char)[] kind, const(char)[] which) {
    Buf p; p.put("/objects/"); p.put(kind); p.put('/'); p.put(nameOf(o)); p.put('/'); p.put(which);
    auto t = readQuiet(p.str()); p.dispose();
    if (!t) return err("no ", which, " for ", nameOf(o));
    return t;
}
private Value* capsOf(Value* o, const(char)[] kind) {
    auto t = fieldFile(o, kind, "capabilities"); if (!t) return null;
    ListB lb; auto s = str(t); size_t st = 0;
    foreach (k; 0 .. s.length + 1) if (k == s.length || s[k] == '\n') { auto l = s[st .. k]; st = k + 1; if (l.length && l[0] != '#') lb.push(mkStr(l)); }
    return lb.done();
}
private Value* relsOf(Value* o, const(char)[] kind) {
    auto t = fieldFile(o, kind, "relationships"); if (!t) return null;
    return parseKV(mkRecord(0), str(t));
}
// Domain
private Value* d_start(Value** a, void* c) { return domainAction("start", nameOf(a[0]), null); }
private Value* d_stop(Value** a, void* c) { return domainAction("stop", nameOf(a[0]), null); }
private Value* d_pause(Value** a, void* c) { return domainAction("pause", nameOf(a[0]), null); }
private Value* d_resume(Value** a, void* c) { return domainAction("resume", nameOf(a[0]), null); }
private Value* d_snapshot(Value** a, void* c) { return domainAction("snapshot", nameOf(a[0]), null); }
private Value* d_commit(Value** a, void* c) { return domainAction("commit", nameOf(a[0]), null); }
private Value* d_delete(Value** a, void* c) { if (!guard("delete")) return null; return domainAction("delete", nameOf(a[0]), null); }
private Value* argText(Value* v, ref Buf b) { b.clear(); textOf(b, v); return v; }
private Value* d1(Value** a, const(char)[] verb) { Buf b; argText(a[1], b); auto r = domainAction(verb, nameOf(a[0]), b.str()); b.dispose(); return r; }
private Value* d_clone(Value** a, void* c) { Buf b; argText(a[1], b); auto r = domainAction("clone", nameOf(a[0]), b.str()); b.dispose(); return r; }
private Value* d_route(Value** a, void* c) { return d1(a, "route"); }
private Value* d_usbOn(Value** a, void* c) { return d1(a, "usbon"); }
private Value* d_usbOff(Value** a, void* c) { return d1(a, "usboff"); }
private Value* d_devOn(Value** a, void* c) { return d1(a, "devon"); }
private Value* d_devOff(Value** a, void* c) { return d1(a, "devoff"); }
private Value* d_grant(Value** a, void* c) { return d1(a, "port"); }
private Value* d_revoke(Value** a, void* c) { return d1(a, "unport"); }
private Value* d_distro(Value** a, void* c) { return d1(a, "distro"); }
private Value* d_spawn(Value** a, void* c) { return d1(a, "spawn"); }
private Value* d_ping(Value** a, void* c) { return domainAction("ping", nameOf(a[0]), null); }
private Value* d_caps(Value** a, void* c) { return capsOf(a[0], "domains"); }
private Value* d_rels(Value** a, void* c) { return relsOf(a[0], "domains"); }
private Value* d_fs(Value** a, void* c) { auto t = fieldFile(a[0], "domains", "fs"); if (!t) return null; return linesToList(str(t)); }
private Value* d_apps(Value** a, void* c) {
    auto all = c_apps(null, null); if (!all) return null;
    const me = nameOf(a[0]);
    ListB lb;
    foreach (k; 0 .. all.n) {
        auto ds = fieldS(all.items[k], "domains");
        if (ds && ds.t == VT.List) foreach (j; 0 .. ds.n) if (ds.items[j].t == VT.Str && str(ds.items[j]) == me) { lb.push(fieldS(all.items[k], "id")); break; }
    }
    return lb.done();
}
private Value* d_refresh(Value** a, void* c) { return loadObject("domains", "Domain", nameOf(a[0]), jsonDoc("/config/domains.json")); }
// Identity / Service / User
private Value* i_caps(Value** a, void* c) { return capsOf(a[0], "identities"); }
private Value* i_rels(Value** a, void* c) { return relsOf(a[0], "identities"); }
private Value* i_switch(Value** a, void* c) {
    if (g_pure) return err("(switch has effects)");
    if (!guard("identity switch")) return null;
    if (g_dryRun) { out_("dry-run: would switch this shell to identity "); out_(nameOf(a[0])); outc('\n'); return g_unit; }
    auto z = cz(nameOf(a[0]));
    const r = syscall(HOS_SYS_QUERY, HOSQ_ID_SWITCH, 0, cast(long)z, 0); free(z);
    if (r < 0) return err(errnoNow() == 1 ? "identity switch refused: only toward less authority" : "identity switch refused");
    return g_unit;
}
private Value* sv_caps(Value** a, void* c) { return capsOf(a[0], "services"); }
private Value* sv_rels(Value** a, void* c) { return relsOf(a[0], "services"); }
private Value* u_caps(Value** a, void* c) { return capsOf(a[0], "users"); }
private Value* u_rels(Value** a, void* c) { return relsOf(a[0], "users"); }
// Namespace
private Value* n_enter(Value** a, void* c) {
    if (g_pure) return err("(enter has effects)");
    if (!guard("namespace enter")) return null;
    auto id = fieldS(a[0], "objId");
    if (!id || id.t != VT.Int) return err("this namespace has no objId");
    if (g_dryRun) { out_("dry-run: would enter namespace "); outi(id.i); outc('\n'); return g_unit; }
    const r = syscall(HOS_SYS_QUERY, HOSQ_NS_ENTER, id.i, 0, 0);
    if (r < 0) return err("namespace enter refused (only namespaces this shell owns)");
    return g_unit;
}
private Value* c_nsClone(Value** a, void* c) {
    if (g_pure) return err("(nsClone has effects)");
    const r = syscall(HOS_SYS_QUERY, HOSQ_NS_CLONE, 0, 0, 0);
    if (r < 0) return err("namespace clone refused");
    return mkInt(r);
}
// Process
private Value* p_kill(Value** a, void* c) {
    if (g_pure) return err("(kill has effects)");
    auto pid = fieldS(a[0], "pid"); if (!pid || pid.t != VT.Int) return err("no pid");
    if (kill(cast(int)pid.i, SIGTERM) != 0) return err("kill failed");
    return g_unit;
}
private Value* p_signal(Value** a, void* c) {
    if (g_pure) return err("(signal has effects)");
    auto pid = fieldS(a[0], "pid"); if (!pid || pid.t != VT.Int || a[1].t != VT.Int) return err("signal: expected an Int");
    if (kill(cast(int)pid.i, cast(int)a[1].i) != 0) return err("signal failed");
    return g_unit;
}
// App
private Value* ap_grant(Value** a, void* c) { Buf b; argText(a[1], b); auto id = fieldS(a[0], "id"); Buf i; if (id) textOf(i, id); auto r = domainAction("port", b.str(), i.str()); b.dispose(); i.dispose(); return r; }
private Value* ap_revoke(Value** a, void* c) { Buf b; argText(a[1], b); auto id = fieldS(a[0], "id"); Buf i; if (id) textOf(i, id); auto r = domainAction("unport", b.str(), i.str()); b.dispose(); i.dispose(); return r; }
// UsbDevice
private Value* us_allow(Value** a, void* c) { Buf b; argText(a[1], b); auto id = fieldS(a[0], "id"); Buf i; if (id) textOf(i, id); auto r = domainAction("usbon", b.str(), i.str()); b.dispose(); i.dispose(); return r; }
private Value* us_deny(Value** a, void* c) { Buf b; argText(a[1], b); auto id = fieldS(a[0], "id"); Buf i; if (id) textOf(i, id); auto r = domainAction("usboff", b.str(), i.str()); b.dispose(); i.dispose(); return r; }
// JSON
private Value* j_parse(Value** a, void* c) { if (a[0].t != VT.Str) return err("parseJson: expected a String"); return parseJson(str(a[0])); }
private Value* j_show(Value** a, void* c) { Buf b; toJson(b, a[0]); auto r = mkStr(b.str()); b.dispose(); return r; }
private Value* j_file(Value** a, void* c) { if (a[0].t != VT.Str) return err("readJson: expected a path"); auto t = readWholeFile(str(a[0])); if (!t) return null; return parseJson(str(t)); }

void objectsInit() {
    defPrim("domains", 0, &c_domains, "[Domain]", "every domain (identity sandbox) on this system");
    defPrim("domain", 1, &c_domain, "String -> Domain", "a domain by name");
    defPrim("identities", 0, &c_identities, "[Identity]", "every identity (authority ceiling)");
    defPrim("identity", 1, &c_identity, "String -> Identity", "an identity by name");
    defPrim("services", 0, &c_services, "[Service]", "every kernel service");
    defPrim("service", 1, &c_service, "String -> Service", "a service by name");
    defPrim("users", 0, &c_users, "[User]", "every user");
    defPrim("user", 1, &c_user, "String -> User", "a user by name");
    defPrim("namespaces", 0, &c_namespaces, "[Namespace]", "every namespace");
    defPrim("nsClone", 0, &c_nsClone, "Int", "clone this shell's namespace (returns its objId)");
    defPrim("objects", 0, &c_objects, "[ObjCount]", "the live kernel object table (type, count)");
    defPrim("me", 0, &c_me, "Me", "who this shell is: user, namespace, rights, domain");
    defPrim("system", 0, &c_system, "System", "the system summary and its declared configuration");
    defPrim("apps", 0, &c_apps, "[App]", "every application and the domains it is delegated to");
    defPrim("app", 1, &c_app, "String -> App", "an application by id");
    defPrim("usbDevices", 0, &c_usb, "[UsbDevice]", "the USB devices and which domains may use them");
    defPrim("network", 0, &c_vnet, "Record", "the virtual networks: segments, ports, routes (/config/vnet.json)");
    defPrim("procs", 0, &c_procs, "[Process]", "running processes");
    defPrim("parseJson", 1, &j_parse, "String -> a", "JSON text as a dash value");
    defPrim("toJson", 1, &j_show, "a -> String", "a value as JSON text");
    defPrim("readJson", 1, &j_file, "String -> a", "a JSON file as a dash value");

    // Domain
    defFieldDoc("Domain", "name", "String", "the domain's name");
    defFieldDoc("Domain", "objId", "Int", "kernel object id");
    defFieldDoc("Domain", "identity", "String", "the identity it runs as");
    defFieldDoc("Domain", "state", "String", "defined / running / paused / stopped");
    defFieldDoc("Domain", "type", "String", "domain or template");
    defFieldDoc("Domain", "persist", "String", "ephemeral / home-only / full");
    defMethod("Domain", "start", 0, &d_start, "()", "start it", true);
    defMethod("Domain", "stop", 0, &d_stop, "()", "stop it", true);
    defMethod("Domain", "pause", 0, &d_pause, "()", "pause it", true);
    defMethod("Domain", "resume", 0, &d_resume, "()", "resume it", true);
    defMethod("Domain", "snapshot", 0, &d_snapshot, "()", "take a snapshot", true);
    defMethod("Domain", "commit", 0, &d_commit, "()", "commit its changes", true);
    defMethod("Domain", "delete", 0, &d_delete, "()", "delete it (needs `arm`)", true);
    defMethod("Domain", "ping", 0, &d_ping, "()", "check that it answers", true);
    defMethod("Domain", "clone", 1, &d_clone, "String -> ()", "clone it under a new name", true);
    defMethod("Domain", "route", 1, &d_route, "String -> ()", "route its traffic: \"direct\", \"vm:<segment>\" or \"domain:<name>\"", true);
    defMethod("Domain", "usbOn", 1, &d_usbOn, "String -> ()", "give it a USB device (\"vid:pid\")", true);
    defMethod("Domain", "usbOff", 1, &d_usbOff, "String -> ()", "take a USB device away", true);
    defMethod("Domain", "devOn", 1, &d_devOn, "String -> ()", "allow a device class (gpu audio camera mic usb input virt)", true);
    defMethod("Domain", "devOff", 1, &d_devOff, "String -> ()", "deny a device class", true);
    defMethod("Domain", "grant", 1, &d_grant, "String -> ()", "delegate an application to it", true);
    defMethod("Domain", "revoke", 1, &d_revoke, "String -> ()", "take an application back", true);
    defMethod("Domain", "distro", 1, &d_distro, "String -> ()", "set its Linux distribution (busybox alpine nix native)", true);
    defMethod("Domain", "spawn", 1, &d_spawn, "String -> ()", "start a program inside it", true);
    defMethod("Domain", "caps", 0, &d_caps, "[String]", "its capability ceiling");
    defMethod("Domain", "relationships", 0, &d_rels, "Record", "its object-graph edges (identity, namespace, overlay...)");
    defMethod("Domain", "fs", 0, &d_fs, "[String]", "its filesystem view (bindings)");
    defMethod("Domain", "apps", 0, &d_apps, "[String]", "the applications delegated to it");
    defMethod("Domain", "refresh", 0, &d_refresh, "Domain", "the same domain, re-read from the kernel");
    // Identity
    defFieldDoc("Identity", "name", "String", "the identity's name");
    defFieldDoc("Identity", "trust", "Int", "trust level");
    defFieldDoc("Identity", "ceiling", "Int", "rights ceiling (bitmask)");
    defFieldDoc("Identity", "state", "String", "active / draft");
    defFieldDoc("Identity", "disposable", "Bool", "wiped when closed");
    defMethod("Identity", "caps", 0, &i_caps, "[String]", "its capability ceiling, decoded");
    defMethod("Identity", "relationships", 0, &i_rels, "Record", "its object-graph edges");
    defMethod("Identity", "switch", 0, &i_switch, "()", "run this shell as it (less authority only; needs `arm`)", true);
    // Service
    defFieldDoc("Service", "name", "String", "the service's name");
    defFieldDoc("Service", "state", "String", "started / stopped");
    defFieldDoc("Service", "rights", "Int", "authority it holds");
    defFieldDoc("Service", "version", "Int", "version");
    defMethod("Service", "caps", 0, &sv_caps, "[String]", "the authority it holds, decoded");
    defMethod("Service", "relationships", 0, &sv_rels, "Record", "owner, endpoint, generation");
    // User
    defFieldDoc("User", "name", "String", "user name");
    defFieldDoc("User", "uid", "Int", "user id");
    defFieldDoc("User", "gid", "Int", "group id");
    defMethod("User", "caps", 0, &u_caps, "[String]", "administrative authority, decoded");
    defMethod("User", "relationships", 0, &u_rels, "Record", "uid, gid");
    // Namespace
    defFieldDoc("Namespace", "objId", "Int", "namespace object id");
    defMethod("Namespace", "enter", 0, &n_enter, "()", "move this shell into it (owned namespaces; needs `arm`)", true);
    // Process
    defFieldDoc("Process", "pid", "Int", "process id");
    defFieldDoc("Process", "name", "String", "program name");
    defFieldDoc("Process", "state", "String", "run state");
    defFieldDoc("Process", "ppid", "Int", "parent process id");
    defFieldDoc("Process", "rssKb", "Int", "resident memory (KiB)");
    defMethod("Process", "kill", 0, &p_kill, "()", "terminate it (SIGTERM)", true);
    defMethod("Process", "signal", 1, &p_signal, "Int -> ()", "send a signal", true);
    // App
    defFieldDoc("App", "id", "String", "application id");
    defFieldDoc("App", "delegable", "Bool", "may other domains be given it");
    defFieldDoc("App", "host", "String", "where a desktop launch lands (session / system)");
    defFieldDoc("App", "domains", "[String]", "the domains it is delegated to");
    defMethod("App", "grant", 1, &ap_grant, "String -> ()", "delegate it to a domain", true);
    defMethod("App", "revoke", 1, &ap_revoke, "String -> ()", "take it back from a domain", true);
    // UsbDevice
    defFieldDoc("UsbDevice", "id", "String", "vendor:product");
    defFieldDoc("UsbDevice", "name", "String", "device name");
    defFieldDoc("UsbDevice", "domains", "[String]", "domains that may use it now");
    defMethod("UsbDevice", "allow", 1, &us_allow, "String -> ()", "let a domain use it", true);
    defMethod("UsbDevice", "deny", 1, &us_deny, "String -> ()", "stop a domain using it", true);
    // Me / System / ObjCount
    defFieldDoc("Me", "user", "String", "user name");
    defFieldDoc("Me", "namespace", "String", "this shell's namespace");
    defFieldDoc("Me", "rights", "String", "this shell's rights");
    defFieldDoc("Me", "domain", "String", "this shell's domain");
    defFieldDoc("System", "summary", "String", "one-line system summary");
    defFieldDoc("ObjCount", "type", "String", "kernel object type");
    defFieldDoc("ObjCount", "count", "Int", "how many exist");
}
