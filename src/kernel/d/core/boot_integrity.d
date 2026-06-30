// boot_integrity.d - ZKsync-anchored boot-module hash verification.
module core.boot_integrity;

import core.io : klog, klog_hex;
import core.console : console_force_framebuffer_log;
import core.exports : g_mboot_modules, g_module_count, phys_to_virt;
import core.crypto : Sha256, sha256Init, sha256Update, sha256Final, sha256, ctEqual32;
import core.install_config : installConfigBootIntegrityZkSync;
import network.stack : isNetworkStackRunning;
import network.https : httpsPostHostname;
import network.http : HTTPResponse, httpPost;

extern (C) @nogc nothrow:

align(8) private struct BiBootModuleRecord {
    ulong mod_start;   // 64-bit phys: must match boot_module_record_t (modules can load >4 GiB)
    ulong mod_end;
    char[112] name;
}

private enum uint BI_JSON_MAX = 65536;
private enum uint BI_MAX_FILES = 384;
private enum uint BI_PATH_MAX = 128;
private enum uint BI_ADDR_MAX = 64;
private enum uint BI_URL_MAX = 160;
private enum uint BI_HOST_MAX = 128;
private enum uint BI_RPC_BODY_MAX = 512;
private enum uint BI_LEAF_PREFIX_LEN = 13;
private enum uint BI_SYSTEM_ROOT_SELECTOR_LEN = 10;

private immutable ubyte[BI_LEAF_PREFIX_LEN] BI_LEAF_PREFIX = [
    'e','p','i','n','-','f','i','l','e','-','v','1',0
];

private immutable char[BI_SYSTEM_ROOT_SELECTOR_LEN + 1] BI_SYSTEM_ROOT_SELECTOR = "0x07c1a224\0";

private struct BiEntry {
    char[BI_PATH_MAX] path;
    uint pathLen;
    ubyte[32] expected;
    ubyte[32] actual;
    ubyte[32] leaf;
}

__gshared ubyte[BI_JSON_MAX] g_biJson;
__gshared uint g_biJsonLen;
__gshared BiEntry[BI_MAX_FILES] g_biEntries;
__gshared uint g_biEntryCount;
__gshared ubyte[32][BI_MAX_FILES] g_biLevel;
__gshared ubyte[32] g_biRoot;
__gshared char[BI_ADDR_MAX] g_biContractAddress;
__gshared uint g_biContractAddressLen;
__gshared char[BI_URL_MAX] g_biRpcUrl;
__gshared uint g_biRpcUrlLen;
__gshared char[BI_HOST_MAX] g_biRpcHost;
__gshared uint g_biRpcHostLen;
__gshared ushort g_biRpcPort;
__gshared bool g_biRpcUseTls;
__gshared bool g_biSelected;
__gshared bool g_biLocalOk;
__gshared bool g_biChainAttempted;
__gshared bool g_biChainOk;

private void biPanic(const(char)* msg) {
    console_force_framebuffer_log();
    klog("[boot-integrity] FATAL: ");
    klog(msg);
    klog("\n");
    while (true) { asm @nogc nothrow { cli; hlt; } }
}

private bool biStrEq(const(char)* a, const(char)* b) {
    while (*a != 0 && *b != 0) {
        if (*a != *b) return false;
        ++a; ++b;
    }
    return *a == *b;
}

private bool biNameEqLen(const(char)* a, const(char)* b, uint bLen) {
    uint i = 0;
    while (i < bLen && a[i] != 0) {
        if (a[i] != b[i]) return false;
        ++i;
    }
    return i == bLen && a[i] == 0;
}

private const(char)* biBaseName(const(char)* nm) {
    const(char)* base = nm;
    for (const(char)* p = nm; *p != 0; ++p) {
        if (*p == '/') base = p + 1;
    }
    return base;
}

private bool biFindModuleByBase(const(char)* want, uint wantLen, out ulong phys, out ulong size) {
    phys = 0; size = 0;
    if (g_mboot_modules is null || g_module_count <= 0 || want is null || wantLen == 0) return false;
    auto recs = cast(const(BiBootModuleRecord)*) g_mboot_modules;
    for (int i = 0; i < g_module_count; i++) {
        const(char)* base = biBaseName(cast(const(char)*)&recs[i].name[0]);
        if (biNameEqLen(base, want, wantLen)) {
            phys = cast(ulong)recs[i].mod_start;
            size = cast(ulong)recs[i].mod_end - cast(ulong)recs[i].mod_start;
            return true;
        }
    }
    return false;
}

private bool biFindModuleC(const(char)* want, out ulong phys, out ulong size) {
    uint len = 0;
    while (want[len] != 0) ++len;
    return biFindModuleByBase(want, len, phys, size);
}

private bool biWhitespace(char c) {
    return c == ' ' || c == '\n' || c == '\r' || c == '\t';
}

private bool biKeyEq(size_t p, string key, out size_t afterQuote) {
    afterQuote = p;
    if (p >= g_biJsonLen || cast(char)g_biJson[p] != '"') return false;
    ++p;
    foreach (i; 0 .. key.length) {
        if (p + i >= g_biJsonLen || cast(char)g_biJson[p + i] != key[i]) return false;
    }
    p += key.length;
    if (p >= g_biJsonLen || cast(char)g_biJson[p] != '"') return false;
    afterQuote = p + 1;
    return true;
}

private bool biReadJsonString(size_t p, char[] outBuf, ref uint outLen, out size_t after) {
    outLen = 0;
    after = p;
    if (p >= g_biJsonLen || cast(char)g_biJson[p] != '"') return false;
    ++p;
    while (p < g_biJsonLen) {
        char c = cast(char)g_biJson[p++];
        if (c == '"') {
            if (outLen < outBuf.length) outBuf[outLen] = 0;
            after = p;
            return true;
        }
        if (c == '\\' && p < g_biJsonLen) {
            char e = cast(char)g_biJson[p++];
            if (e == '"' || e == '\\' || e == '/') c = e;
            else if (e == 'n') c = '\n';
            else if (e == 't') c = '\t';
            else c = e;
        }
        if (c >= 0x20 && c < 0x7f && outLen + 1 < outBuf.length)
            outBuf[outLen++] = c;
    }
    return false;
}

private bool biJsonGetStringFrom(string key, size_t start, char[] outBuf, ref uint outLen, out size_t after) {
    outLen = 0;
    after = start;
    foreach (p0; start .. cast(size_t)g_biJsonLen) {
        size_t p;
        if (!biKeyEq(p0, key, p)) continue;
        while (p < g_biJsonLen && biWhitespace(cast(char)g_biJson[p])) ++p;
        if (p >= g_biJsonLen || cast(char)g_biJson[p] != ':') continue;
        ++p;
        while (p < g_biJsonLen && biWhitespace(cast(char)g_biJson[p])) ++p;
        if (biReadJsonString(p, outBuf, outLen, after)) return true;
    }
    return false;
}

private bool biJsonGetString(string key, char[] outBuf, ref uint outLen) {
    size_t after;
    return biJsonGetStringFrom(key, 0, outBuf, outLen, after);
}

private int biHexVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

private bool biParseHex32(const(char)* src, uint len, ubyte* out32) {
    uint off = 0;
    if (len == 66 && src[0] == '0' && (src[1] == 'x' || src[1] == 'X')) off = 2;
    else if (len != 64) return false;
    foreach (i; 0 .. 32) {
        int hi = biHexVal(src[off + i * 2]);
        int lo = biHexVal(src[off + i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out32[i] = cast(ubyte)((hi << 4) | lo);
    }
    return true;
}

private bool biContractAddressConfigured() {
    if (g_biContractAddressLen != 42) return false;
    if (g_biContractAddress[0] != '0' || (g_biContractAddress[1] != 'x' && g_biContractAddress[1] != 'X'))
        return false;
    bool nonzero = false;
    foreach (i; 2 .. 42) {
        if (biHexVal(g_biContractAddress[i]) < 0) return false;
        if (g_biContractAddress[i] != '0') nonzero = true;
    }
    return nonzero;
}

private bool biExtractRpcHost() {
    g_biRpcHostLen = 0;
    g_biRpcUseTls = true;
    g_biRpcPort = 443;
    const(char)* fallback = "sepolia.era.zksync.dev\0".ptr;
    if (g_biRpcUrlLen == 0) {
        while (fallback[g_biRpcHostLen] != 0 && g_biRpcHostLen + 1 < BI_HOST_MAX) {
            g_biRpcHost[g_biRpcHostLen] = fallback[g_biRpcHostLen];
            ++g_biRpcHostLen;
        }
        g_biRpcHost[g_biRpcHostLen] = 0;
        return true;
    }

    uint p = 0;
    if (g_biRpcUrlLen > 8 &&
        g_biRpcUrl[0] == 'h' && g_biRpcUrl[1] == 't' && g_biRpcUrl[2] == 't' && g_biRpcUrl[3] == 'p' &&
        g_biRpcUrl[4] == 's' && g_biRpcUrl[5] == ':' && g_biRpcUrl[6] == '/' && g_biRpcUrl[7] == '/') {
        p = 8;
    } else if (g_biRpcUrlLen > 7 &&
        g_biRpcUrl[0] == 'h' && g_biRpcUrl[1] == 't' && g_biRpcUrl[2] == 't' && g_biRpcUrl[3] == 'p' &&
        g_biRpcUrl[4] == ':' && g_biRpcUrl[5] == '/' && g_biRpcUrl[6] == '/') {
        p = 7;
        g_biRpcUseTls = false;
        g_biRpcPort = 80;
    }

    while (p < g_biRpcUrlLen && g_biRpcUrl[p] != '/' && g_biRpcUrl[p] != ':' && g_biRpcHostLen + 1 < BI_HOST_MAX) {
        g_biRpcHost[g_biRpcHostLen++] = g_biRpcUrl[p++];
    }
    if (p < g_biRpcUrlLen && g_biRpcUrl[p] == ':') {
        ++p;
        uint port = 0;
        while (p < g_biRpcUrlLen && g_biRpcUrl[p] >= '0' && g_biRpcUrl[p] <= '9') {
            port = port * 10 + cast(uint)(g_biRpcUrl[p] - '0');
            ++p;
        }
        if (port > 0 && port <= 65535) g_biRpcPort = cast(ushort)port;
    }
    g_biRpcHost[g_biRpcHostLen] = 0;
    return g_biRpcHostLen > 0;
}

private bool biLoadAttestation() {
    g_biJsonLen = 0;
    ulong phys, size;
    if (!biFindModuleC("zksync-attestation.json\0".ptr, phys, size)) return false;
    if (size == 0 || size >= BI_JSON_MAX) return false;
    const(ubyte)* src = cast(const(ubyte)*)phys_to_virt(phys);
    foreach (i; 0 .. size) g_biJson[cast(size_t)i] = src[cast(size_t)i];
    g_biJsonLen = cast(uint)size;
    g_biJson[g_biJsonLen] = 0;
    return true;
}

private bool biParseEntries() {
    g_biEntryCount = 0;
    char[BI_PATH_MAX] path;
    char[80] hex;
    uint pathLen = 0;
    uint hexLen = 0;
    size_t cursor = 0;
    while (g_biEntryCount < BI_MAX_FILES) {
        size_t afterPath;
        if (!biJsonGetStringFrom("path", cursor, path[], pathLen, afterPath)) break;
        size_t afterHash;
        if (!biJsonGetStringFrom("sha256", afterPath, hex[], hexLen, afterHash)) return false;
        if (pathLen == 0 || pathLen >= BI_PATH_MAX) return false;
        auto e = &g_biEntries[g_biEntryCount];
        e.pathLen = pathLen;
        foreach (i; 0 .. pathLen) e.path[i] = path[i];
        e.path[pathLen] = 0;
        if (!biParseHex32(hex.ptr, hexLen, e.expected.ptr)) return false;
        ++g_biEntryCount;
        cursor = afterHash;
    }
    return g_biEntryCount > 0;
}

private bool biHashEntriesAndCompare() {
    foreach (idx; 0 .. g_biEntryCount) {
        auto e = &g_biEntries[idx];
        ulong phys, size;
        if (!biFindModuleByBase(e.path.ptr, e.pathLen, phys, size)) {
            klog("[boot-integrity] missing module ");
            klog(e.path.ptr);
            klog("\n");
            return false;
        }
        const(ubyte)* data = cast(const(ubyte)*)phys_to_virt(phys);
        sha256(data, size, e.actual.ptr);
        if (!ctEqual32(e.actual.ptr, e.expected.ptr)) {
            klog("[boot-integrity] hash mismatch ");
            klog(e.path.ptr);
            klog("\n");
            return false;
        }

        Sha256 s;
        sha256Init(s);
        sha256Update(s, BI_LEAF_PREFIX.ptr, BI_LEAF_PREFIX_LEN);
        sha256Update(s, cast(const(ubyte)*)e.path.ptr, e.pathLen);
        ubyte zero = 0;
        sha256Update(s, &zero, 1);
        sha256Update(s, e.actual.ptr, 32);
        sha256Final(s, e.leaf.ptr);
        foreach (j; 0 .. 32) g_biLevel[idx][j] = e.leaf[j];
    }

    uint count = g_biEntryCount;
    while (count > 1) {
        uint outCount = 0;
        for (uint i = 0; i < count; i += 2) {
            uint right = i + 1 < count ? i + 1 : i;
            ubyte[64] pair;
            foreach (j; 0 .. 32) pair[j] = g_biLevel[i][j];
            foreach (j; 0 .. 32) pair[32 + j] = g_biLevel[right][j];
            sha256(pair.ptr, 64, g_biLevel[outCount].ptr);
            ++outCount;
        }
        count = outCount;
    }
    return ctEqual32(g_biLevel[0].ptr, g_biRoot.ptr);
}

public void bootIntegrityVerifyLocal() {
    g_biSelected = installConfigBootIntegrityZkSync();
    g_biLocalOk = false;
    g_biChainAttempted = false;
    g_biChainOk = false;
    if (!g_biSelected) {
        klog("[boot-integrity] zkSync attestation not selected\n");
        return;
    }

    if (!biLoadAttestation()) biPanic("selected but zksync-attestation.json is missing or too large");

    char[80] rootHex;
    uint rootHexLen = 0;
    if (!biJsonGetString("root", rootHex[], rootHexLen) || !biParseHex32(rootHex.ptr, rootHexLen, g_biRoot.ptr))
        biPanic("attestation root is missing or invalid");

    g_biContractAddressLen = 0;
    biJsonGetString("contractAddress", g_biContractAddress[], g_biContractAddressLen);
    if (!biContractAddressConfigured())
        biPanic("zkSync registry contractAddress is not configured");

    g_biRpcUrlLen = 0;
    biJsonGetString("rpcUrl", g_biRpcUrl[], g_biRpcUrlLen);
    if (!biExtractRpcHost())
        biPanic("rpcUrl host is invalid");

    if (!biParseEntries()) biPanic("attestation file list is missing or invalid");
    if (!biHashEntriesAndCompare()) biPanic("local boot-module hashes do not match attestation root");

    g_biLocalOk = true;
    klog("[boot-integrity] local manifest OK files=");
    klog_hex(g_biEntryCount);
    klog(" root=");
    klog_hex((cast(ulong)g_biRoot[0] << 56) | (cast(ulong)g_biRoot[1] << 48) |
             (cast(ulong)g_biRoot[2] << 40) | (cast(ulong)g_biRoot[3] << 32) |
             (cast(ulong)g_biRoot[4] << 24) | (cast(ulong)g_biRoot[5] << 16) |
             (cast(ulong)g_biRoot[6] << 8) | cast(ulong)g_biRoot[7]);
    klog("...\n");
}

private bool biAppend(char* buf, size_t cap, ref size_t pos, const(char)* s) {
    for (size_t i = 0; s[i] != 0; ++i) {
        if (pos + 1 >= cap) return false;
        buf[pos++] = s[i];
    }
    return true;
}

private bool biAppendSlice(char* buf, size_t cap, ref size_t pos, const(char)* s, uint len) {
    foreach (i; 0 .. len) {
        if (pos + 1 >= cap) return false;
        buf[pos++] = s[i];
    }
    return true;
}

private bool biBuildEthCallBody(char* outBuf, size_t cap, ref size_t len) {
    len = 0;
    if (!biAppend(outBuf, cap, len, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_call\",\"params\":[{\"to\":\"\0".ptr)) return false;
    if (!biAppendSlice(outBuf, cap, len, g_biContractAddress.ptr, g_biContractAddressLen)) return false;
    if (!biAppend(outBuf, cap, len, "\",\"data\":\"\0".ptr)) return false;
    if (!biAppend(outBuf, cap, len, BI_SYSTEM_ROOT_SELECTOR.ptr)) return false;
    if (!biAppend(outBuf, cap, len, "\"},\"latest\"]}\0".ptr)) return false;
    return true;
}

private bool biFindResultRoot(const(ubyte)* body, size_t len, ubyte* out32) {
    for (size_t i = 0; i + 10 < len; ++i) {
        if (body[i] != '"' || body[i + 1] != 'r' || body[i + 2] != 'e' || body[i + 3] != 's' ||
            body[i + 4] != 'u' || body[i + 5] != 'l' || body[i + 6] != 't' || body[i + 7] != '"')
            continue;
        size_t p = i + 8;
        while (p < len && body[p] != '0') ++p;
        if (p + 66 > len || body[p] != '0' || (body[p + 1] != 'x' && body[p + 1] != 'X')) return false;
        char[66] hex;
        foreach (j; 0 .. 66) hex[j] = cast(char)body[p + j];
        return biParseHex32(hex.ptr, 66, out32);
    }
    return false;
}

public void bootIntegrityVerifyChain() {
    if (!g_biSelected) return;
    if (!g_biLocalOk) biPanic("chain check reached before local verification passed");
    if (g_biChainAttempted) return;
    g_biChainAttempted = true;

    if (!isNetworkStackRunning())
        biPanic("network is not running for selected zkSync attestation");

    char[BI_RPC_BODY_MAX] body;
    size_t bodyLen = 0;
    if (!biBuildEthCallBody(body.ptr, body.length, bodyLen))
        biPanic("failed to build eth_call request");

    HTTPResponse response;
    klog("[boot-integrity] querying zkSync registry host=");
    klog(g_biRpcHost.ptr);
    klog("\n");
    bool sent = false;
    if (g_biRpcUseTls)
        sent = httpsPostHostname(g_biRpcHost.ptr, "/\0".ptr, cast(const(ubyte)*)body.ptr, bodyLen, &response);
    else
        sent = httpPost(g_biRpcHost.ptr, g_biRpcPort, "/\0".ptr, cast(const(ubyte)*)body.ptr, bodyLen, &response);
    if (!sent)
        biPanic("zkSync eth_call request failed");
    if (response.statusCode != 200)
        biPanic("zkSync RPC returned non-200 status");

    ubyte[32] chainRoot;
    if (!biFindResultRoot(response.body.ptr, response.bodyLen, chainRoot.ptr))
        biPanic("zkSync RPC response did not contain systemRoot()");
    if (!ctEqual32(chainRoot.ptr, g_biRoot.ptr))
        biPanic("zkSync registry root does not match local attestation");

    g_biChainOk = true;
    klog("[boot-integrity] zkSync registry root OK\n");
}
