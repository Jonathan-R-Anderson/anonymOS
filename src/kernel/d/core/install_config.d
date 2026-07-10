// install_config.d — first-boot consumption of installer-captured install.json.
//
// The live installer sends the captured wizard config to /config/install.action.
// The installer backend writes that JSON into the installed ESP as /install.json
// and the installed Limine config loads it as a boot module. This module consumes
// that boot module before PID1 starts and applies the parts this kernel owns:
// default account identity, hostname, and decoy metadata state.
module core.install_config;

import core.io : klog;
import core.exports : g_mboot_modules, g_module_count, phys_to_virt;
import core.user : userApplyDefaultInstall;
import core.syscalls.posix : posixSetBootHostname;

extern (C) @nogc nothrow:

align(8) private struct IcBootModuleRecord {
    ulong mod_start;   // 64-bit phys: must match boot_module_record_t (modules can load >4 GiB)
    ulong mod_end;
    char[112] name;
}

private enum size_t IC_JSON_MAX = 8192;
private enum size_t IC_FIELD_MAX = 96;

__gshared char[IC_JSON_MAX] g_icJson;
__gshared uint g_icJsonLen;
__gshared bool g_icApplied;
__gshared bool g_icPresent;
__gshared bool g_icRealPasswordSet;
__gshared bool g_icHiddenPasswordSet;
__gshared bool g_icOuterPasswordSet;
__gshared bool g_icDecoyBootPasswordSet;
__gshared bool g_icDecoyPasswordSet;

__gshared char[IC_FIELD_MAX] g_icUser;
__gshared uint g_icUserLen;
__gshared char[IC_FIELD_MAX] g_icHostname;
__gshared uint g_icHostnameLen;
__gshared char[IC_FIELD_MAX] g_icEncryption;
__gshared uint g_icEncryptionLen;
__gshared char[IC_FIELD_MAX] g_icLocale;
__gshared uint g_icLocaleLen;
__gshared char[IC_FIELD_MAX] g_icKeymap;
__gshared uint g_icKeymapLen;
__gshared char[IC_FIELD_MAX] g_icTimezone;
__gshared uint g_icTimezoneLen;
__gshared char[IC_FIELD_MAX] g_icFilesystem;
__gshared uint g_icFilesystemLen;
__gshared char[IC_FIELD_MAX] g_icBootIntegrity;
__gshared uint g_icBootIntegrityLen;
__gshared char[IC_FIELD_MAX] g_icIdentities;
__gshared uint g_icIdentitiesLen;
__gshared char[IC_FIELD_MAX] g_icDrivers;      // comma-joined driver codes chosen in the installer
__gshared uint g_icDriversLen;
__gshared char[IC_FIELD_MAX] g_icDecoyUser;
__gshared uint g_icDecoyUserLen;
__gshared char[IC_FIELD_MAX] g_icDecoyFullName;
__gshared uint g_icDecoyFullNameLen;
__gshared char[IC_FIELD_MAX] g_icDecoyHostname;
__gshared uint g_icDecoyHostnameLen;

public bool installConfigPresent() {
    return g_icPresent;
}

public bool installConfigBootIntegrityZkSync() {
    if (g_icBootIntegrityLen != 6) return false;
    return g_icBootIntegrity[0] == 'z' && g_icBootIntegrity[1] == 'k' &&
           g_icBootIntegrity[2] == 's' && g_icBootIntegrity[3] == 'y' &&
           g_icBootIntegrity[4] == 'n' && g_icBootIntegrity[5] == 'c';
}

private bool icStrEq(const(char)* a, const(char)* b) {
    while (*a != 0 && *b != 0) { if (*a != *b) return false; ++a; ++b; }
    return *a == *b;
}

private bool icFindModule(out ulong phys, out ulong size) {
    phys = 0; size = 0;
    if (g_mboot_modules is null || g_module_count <= 0) return false;
    auto recs = cast(const(IcBootModuleRecord)*) g_mboot_modules;
    for (int i = 0; i < g_module_count; i++) {
        const(char)* nm = cast(const(char)*)&recs[i].name[0];
        const(char)* base = nm;
        for (const(char)* p = nm; *p != 0; ++p) if (*p == '/') base = p + 1;
        if (icStrEq(base, "install.json")) {
            phys = cast(ulong)recs[i].mod_start;
            size = cast(ulong)recs[i].mod_end - cast(ulong)recs[i].mod_start;
            return true;
        }
    }
    return false;
}

private bool icWhitespace(char c) {
    return c == ' ' || c == '\n' || c == '\r' || c == '\t';
}

private bool icKeyEq(size_t p, string key, out size_t afterQuote) {
    afterQuote = p;
    if (p >= g_icJsonLen || g_icJson[p] != '"') return false;
    ++p;
    foreach (i; 0 .. key.length) {
        if (p + i >= g_icJsonLen || g_icJson[p + i] != key[i]) return false;
    }
    p += key.length;
    if (p >= g_icJsonLen || g_icJson[p] != '"') return false;
    afterQuote = p + 1;
    return true;
}

private bool icJsonGetString(string key, char[] outBuf, ref uint outLen) {
    outLen = 0;
    if (g_icJsonLen == 0) return false;
    foreach (p0; 0 .. g_icJsonLen) {
        size_t p;
        if (!icKeyEq(p0, key, p)) continue;
        while (p < g_icJsonLen && icWhitespace(g_icJson[p])) ++p;
        if (p >= g_icJsonLen || g_icJson[p] != ':') continue;
        ++p;
        while (p < g_icJsonLen && icWhitespace(g_icJson[p])) ++p;
        if (p >= g_icJsonLen || g_icJson[p] != '"') continue;
        ++p;
        while (p < g_icJsonLen) {
            char c = g_icJson[p++];
            if (c == '"') {
                if (outLen < outBuf.length) outBuf[outLen] = 0;
                return true;
            }
            if (c == '\\' && p < g_icJsonLen) {
                char e = g_icJson[p++];
                if (e == '"' || e == '\\' || e == '/') c = e;
                else if (e == 'n') c = '\n';
                else if (e == 't') c = '\t';
                else c = e;
            }
            if (c >= 0x20 && c < 0x7f && outLen + 1 < outBuf.length)
                outBuf[outLen++] = c;
        }
    }
    return false;
}

private bool icJsonHasNonEmpty(string key) {
    char[4] tmp;
    uint n = 0;
    return icJsonGetString(key, tmp[], n) && n > 0;
}

private void icLogSlice(const(char)* s, uint len) {
    char[2] ch;
    ch[1] = 0;
    foreach (i; 0 .. len) {
        ch[0] = s[i];
        klog(ch.ptr);
    }
}

public bool installConfigApply() {
    if (g_icApplied) return g_icPresent;
    g_icApplied = true;

    ulong phys, size;
    if (!icFindModule(phys, size)) {
        klog("[install-config] no install.json boot module; using live/default account config\n");
        return false;
    }
    if (size == 0) {
        klog("[install-config] install.json empty; using defaults\n");
        return false;
    }

    ulong copyLen = size;
    if (copyLen >= IC_JSON_MAX) copyLen = IC_JSON_MAX - 1;
    auto src = cast(const(char)*)phys_to_virt(phys);
    foreach (i; 0 .. copyLen) g_icJson[cast(size_t)i] = src[cast(size_t)i];
    g_icJsonLen = cast(uint)copyLen;
    g_icJson[g_icJsonLen] = 0;
    g_icPresent = true;

    bool userOk = false;
    bool hostOk = false;
    if (icJsonGetString("user", g_icUser[], g_icUserLen) && g_icUserLen > 0)
        userOk = userApplyDefaultInstall(g_icUser.ptr, g_icUserLen);
    if (icJsonGetString("hostname", g_icHostname[], g_icHostnameLen) && g_icHostnameLen > 0) {
        posixSetBootHostname(g_icHostname.ptr, g_icHostnameLen);
        hostOk = true;
    }

    icJsonGetString("encryption", g_icEncryption[], g_icEncryptionLen);
    icJsonGetString("locale", g_icLocale[], g_icLocaleLen);
    icJsonGetString("keymap", g_icKeymap[], g_icKeymapLen);
    icJsonGetString("timezone", g_icTimezone[], g_icTimezoneLen);
    icJsonGetString("filesystem", g_icFilesystem[], g_icFilesystemLen);
    icJsonGetString("bootIntegrity", g_icBootIntegrity[], g_icBootIntegrityLen);
    icJsonGetString("identities", g_icIdentities[], g_icIdentitiesLen);
    icJsonGetString("drivers", g_icDrivers[], g_icDriversLen);
    icJsonGetString("decoyUser", g_icDecoyUser[], g_icDecoyUserLen);
    icJsonGetString("decoyFullName", g_icDecoyFullName[], g_icDecoyFullNameLen);
    icJsonGetString("decoyHostname", g_icDecoyHostname[], g_icDecoyHostnameLen);
    g_icRealPasswordSet = icJsonHasNonEmpty("userPasswordSha512") ||
                          icJsonHasNonEmpty("userPassword");
    g_icHiddenPasswordSet = icJsonHasNonEmpty("hiddenPasswordSha512") ||
                            icJsonHasNonEmpty("hiddenPassword");
    g_icOuterPasswordSet = icJsonHasNonEmpty("outerPasswordSha512") ||
                           icJsonHasNonEmpty("outerPassword");
    g_icDecoyBootPasswordSet = icJsonHasNonEmpty("decoyBootPasswordSha512") ||
                               icJsonHasNonEmpty("decoyBootPassword");
    g_icDecoyPasswordSet = icJsonHasNonEmpty("decoyPasswordSha512") ||
                           icJsonHasNonEmpty("decoyPassword");

    klog("[install-config] applied install.json user=");
    if (userOk) icLogSlice(g_icUser.ptr, g_icUserLen); else klog("(default)".ptr);
    klog(" hostname=");
    if (hostOk) icLogSlice(g_icHostname.ptr, g_icHostnameLen); else klog("(default)".ptr);
    klog(" encryption=");
    if (g_icEncryptionLen > 0) icLogSlice(g_icEncryption.ptr, g_icEncryptionLen); else klog("none".ptr);
    klog(" locale=");
    if (g_icLocaleLen > 0) icLogSlice(g_icLocale.ptr, g_icLocaleLen); else klog("(default)".ptr);
    klog(" keymap=");
    if (g_icKeymapLen > 0) icLogSlice(g_icKeymap.ptr, g_icKeymapLen); else klog("(default)".ptr);
    klog(" timezone=");
    if (g_icTimezoneLen > 0) icLogSlice(g_icTimezone.ptr, g_icTimezoneLen); else klog("(default)".ptr);
    klog(" filesystem=");
    if (g_icFilesystemLen > 0) icLogSlice(g_icFilesystem.ptr, g_icFilesystemLen); else klog("(default)".ptr);
    klog(" bootIntegrity=");
    if (g_icBootIntegrityLen > 0) icLogSlice(g_icBootIntegrity.ptr, g_icBootIntegrityLen); else klog("off".ptr);
    if (g_icIdentitiesLen > 0) { klog(" identities="); icLogSlice(g_icIdentities.ptr, g_icIdentitiesLen); }
    if (g_icDriversLen > 0) { klog(" drivers="); icLogSlice(g_icDrivers.ptr, g_icDriversLen); }
    if (g_icDecoyUserLen > 0 || g_icDecoyHostnameLen > 0) {
        klog(" decoy=");
        if (g_icDecoyUserLen > 0) icLogSlice(g_icDecoyUser.ptr, g_icDecoyUserLen);
        klog("@".ptr);
        if (g_icDecoyHostnameLen > 0) icLogSlice(g_icDecoyHostname.ptr, g_icDecoyHostnameLen);
    }
    klog(" passwords(real/hidden/outer/decoyboot/decoy)=");
    klog(g_icRealPasswordSet ? "1" : "0");
    klog(g_icHiddenPasswordSet ? "1" : "0");
    klog(g_icOuterPasswordSet ? "1" : "0");
    klog(g_icDecoyBootPasswordSet ? "1" : "0");
    klog(g_icDecoyPasswordSet ? "1" : "0");
    klog("\n");
    return true;
}
