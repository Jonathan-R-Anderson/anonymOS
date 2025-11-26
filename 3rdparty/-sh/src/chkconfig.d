module chkconfig;

import std.stdio;
import std.string;
import std.file : exists, readText, dirEntries, SpanMode, symlink, remove;
import std.path : baseName;
import std.conv : to;

bool serviceEnabled(string name, int level) {
    string dir = "/etc/rc" ~ to!string(level) ~ ".d";
    if(!exists(dir)) return false;
    foreach(entry; dirEntries(dir, SpanMode.shallow)) {
        auto base = baseName(entry.name);
        if(entry.isSymlink && base.endsWith(name) && base.startsWith("S"))
            return true;
    }
    return false;
}

string listService(string name) {
    string result;
    foreach(lv; 0..7) {
        bool on = serviceEnabled(name, lv);
        result ~= to!string(lv) ~ ":" ~ (on ? "on" : "off") ~ " ";
    }
    return result.strip;
}

void listAll() {
    string dir = "/etc/init.d";
    if(!exists(dir)) { writeln("/etc/init.d not found"); return; }
    foreach(entry; dirEntries(dir, SpanMode.shallow)) {
        auto name = baseName(entry.name);
        writeln(name, " ", listService(name));
    }
}

string parseLevels(string script) {
    foreach(line; script.splitLines) {
        auto idx = line.indexOf("chkconfig:");
        if(idx >= 0) {
            auto parts = line[idx + 10 .. $].split();
            if(parts.length) return parts[0];
        }
    }
    return "2345"; // default
}

void ensureLink(string dir, string name, bool start) {
    foreach(entry; dirEntries(dir, SpanMode.shallow)) {
        auto base = baseName(entry.name);
        if(base.endsWith(name)) {
            remove(entry.name);
        }
    }
    string linkName = (start ? "S50" : "K50") ~ name;
    string dest = dir ~ "/" ~ linkName;
    if(!exists(dest)) {
        try { symlink("../init.d/" ~ name, dest); } catch(Exception) {}
    }
}

void applyLevels(string name, bool[7] startLevels) {
    foreach(lv; 0..7) {
        string dir = "/etc/rc" ~ to!string(lv) ~ ".d";
        if(!exists(dir)) continue;
        ensureLink(dir, name, startLevels[lv]);
    }
}

void addService(string name) {
    string path = "/etc/init.d/" ~ name;
    if(!exists(path)) { writeln("service ", name, " not found"); return; }
    string script = readText(path);
    auto lvStr = parseLevels(script);
    bool[7] startLevels;
    foreach(ch; lvStr) {
        int lv = ch - '0';
        if(lv >= 0 && lv <= 6) startLevels[lv] = true;
    }
    applyLevels(name, startLevels);
}

void delService(string name) {
    foreach(lv; 0..7) {
        string dir = "/etc/rc" ~ to!string(lv) ~ ".d";
        if(!exists(dir)) continue;
        foreach(entry; dirEntries(dir, SpanMode.shallow)) {
            auto base = baseName(entry.name);
            if(base.endsWith(name)) remove(entry.name);
        }
    }
}

void setService(string name, string levels, string action) {
    bool[7] mask;
    if(levels.length == 0) levels = "2345";
    foreach(ch; levels) {
        int lv = ch - '0';
        if(lv >= 0 && lv <=6) mask[lv] = true;
    }
    bool[7] current;
    foreach(lv; 0..7) current[lv] = serviceEnabled(name, lv);
    if(action == "on") {
        foreach(lv; 0..7) if(mask[lv]) current[lv] = true;
    } else if(action == "off") {
        foreach(lv; 0..7) if(mask[lv]) current[lv] = false;
    } else if(action == "reset") {
        string path = "/etc/init.d/" ~ name;
        if(!exists(path)) { writeln("service ", name, " not found"); return; }
        string script = readText(path);
        auto lvStr = parseLevels(script);
        current[] = false;
        foreach(ch; lvStr) { int lv = ch - '0'; if(lv>=0 && lv<=6) current[lv] = true; }
    }
    applyLevels(name, current);
}

void chkconfigCommand(string[] tokens) {
    bool listFlag = false;
    bool addFlag = false;
    bool delFlag = false;
    string levels;
    size_t idx = 1;
    while(idx < tokens.length && tokens[idx].startsWith("--")) {
        auto t = tokens[idx];
        if(t == "--list") {
            listFlag = true;
            idx++;
            break;
        } else if(t == "--add") {
            addFlag = true;
            idx++;
        } else if(t == "--del") {
            delFlag = true;
            idx++;
        } else if(t.startsWith("--level")) {
            if(t.length > 7)
                levels = t[7 .. $];
            else {
                idx++;
                if(idx < tokens.length) levels = tokens[idx];
            }
            idx++;
            continue;
        } else {
            idx++;
            continue;
        }
    }
    string name;
    if(idx < tokens.length) { name = tokens[idx]; idx++; }
    string action;
    if(idx < tokens.length) { action = tokens[idx]; }

    if(listFlag) {
        if(name.length) writeln(name, " ", listService(name));
        else listAll();
        return;
    }
    if(addFlag) { if(name.length) addService(name); else writeln("chkconfig --add name"); return; }
    if(delFlag) { if(name.length) delService(name); else writeln("chkconfig --del name"); return; }
    if(action.length) {
        if(action=="on"||action=="off"||action=="reset") setService(name, levels, action);
        else writeln("chkconfig: invalid action");
    } else if(name.length) {
        auto status = serviceEnabled(name, 3) ? "on" : "off";
        writeln(name, " " , status);
    } else {
        writeln("Usage: chkconfig [--list name] [--add name] [--del name] [--level levels] name <on|off|reset>");
    }
}

