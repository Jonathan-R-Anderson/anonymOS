// SNTP (RFC 4330) client — sets the system wall clock from pool.ntp.org.
//
// Until this existed, clock_gettime() ignored its clk_id and answered every caller with
// milliseconds since boot, so CLOCK_REALTIME reported January 1970 and every file timestamp,
// TLS certificate check and clock applet was wrong by fifty-odd years.
//
// SNTP is deliberately the whole of it: a 48-byte request, one 48-byte reply, and the only field
// that matters is the server's transmit timestamp.  No drift discipline, no peer selection, no
// dispersion tracking — those belong to full NTP, and a kernel that has just learned the year
// does not need them to be correct.
module network.ntp;

import network.types;
import network.udp   : udpSocket, udpBind, udpSend, udpSetCallback, udpClose;
import network.dns   : dnsResolve;
import core.ticks    : pitMs;

@nogc nothrow:

extern(C) void klog(const(char)* s);
extern(C) void klog_dec(ulong v);

// NTP counts seconds from 1900-01-01; Unix counts from 1970-01-01.  The gap is 70 years plus the
// 17 leap days in between: 2_208_988_800 seconds.  Getting this constant wrong is the classic way
// to land 70 years off, so it is spelled out rather than pasted as a magic number.
enum ulong NTP_TO_UNIX_EPOCH = 2_208_988_800UL;

enum ushort NTP_PORT      = 123;
enum ushort NTP_LOCALPORT = 12300;   // fixed local port; this kernel has no ephemeral allocator

// The wall clock, as a Unix-epoch second count that corresponds to g_realtimeAtMs on the PIT.
// Reading the time is then base + (pitMs() - atMs)/1000, so the clock keeps advancing between
// syncs and a later sync simply re-bases it.
private __gshared ulong g_realtimeBaseSec = 0;
private __gshared ulong g_realtimeAtMs    = 0;
private __gshared bool  g_synced          = false;

/// True once a server reply has set the clock.  Callers that must not report a fabricated
/// wall-clock time (rather than an obviously-wrong one) can check this first.
public bool ntpSynced() { return g_synced; }

/// Current wall-clock time in Unix epoch seconds, or 0 if never synced.
public ulong ntpNowSec() {
    if (!g_synced) return 0;
    const ulong now = pitMs();
    const ulong elapsed = (now >= g_realtimeAtMs) ? (now - g_realtimeAtMs) : 0;
    return g_realtimeBaseSec + elapsed / 1000;
}

/// Set the clock directly. Used by the SNTP reply path, and available for a future RTC read.
public void ntpSetRealtime(ulong unixSec) {
    g_realtimeBaseSec = unixSec;
    g_realtimeAtMs    = pitMs();
    g_synced          = true;
}

private __gshared int  g_sock      = -1;
private __gshared bool g_replySeen = false;

// One reply is all SNTP needs.  Bytes 40..47 are the server's transmit timestamp: 32 bits of
// seconds since 1900 followed by a 32-bit binary fraction, both big-endian.  The fraction is
// dropped -- sub-second accuracy is meaningless against this kernel's 1 ms PIT.
private extern(C) void ntpOnPacket(int sockfd, const(ubyte)* data, size_t len,
                                   const ref IPv4Address src, ushort srcPort) {
    if (g_replySeen || data is null || len < 48) return;

    // Leap indicator 3 means "clock not synchronised" -- the server is telling us not to trust it.
    const ubyte li = cast(ubyte)((data[0] >> 6) & 0x3);
    if (li == 3) { klog("[ntp] server reports itself unsynchronised; ignoring reply\n"); return; }

    ulong secs1900 = 0;
    foreach (i; 40 .. 44) secs1900 = (secs1900 << 8) | data[i];
    if (secs1900 <= NTP_TO_UNIX_EPOCH) {
        klog("[ntp] reply timestamp precedes the Unix epoch; ignoring\n");
        return;
    }

    g_replySeen = true;
    const ulong serverSec = secs1900 - NTP_TO_UNIX_EPOCH;

    // On a re-sync, report how far the local clock had drifted before correcting it.  This is the
    // only direct measure of how badly pitMs() tracks real time -- it advances well behind wall
    // clock on this kernel, and ntpNowSec() extrapolates from it between syncs, so the error is
    // worth seeing rather than silently papering over.
    if (g_synced) {
        const ulong before = ntpNowSec();
        klog("[ntp] resync: local clock was ");
        if (serverSec >= before) { klog_dec(serverSec - before); klog(" s SLOW\n"); }
        else                     { klog_dec(before - serverSec); klog(" s FAST\n"); }
    }

    ntpSetRealtime(serverSec);
    klog("[ntp] clock set: unix="); klog_dec(ntpNowSec());
    klog(" from "); klog_dec(src.bytes[0]); klog(".");
    klog_dec(src.bytes[1]); klog("."); klog_dec(src.bytes[2]); klog(".");
    klog_dec(src.bytes[3]); klog("\n");
}

// The resolved pool.ntp.org address, looked up once during the boot network probe rather than
// from the scheduler loop.  dnsResolve() busy-waits while pumping the stack, which is tolerable
// during boot but not on the loop that drives the whole desktop -- and resolving there failed
// anyway while the identical call for example.com succeeded moments earlier in the probe.
private __gshared IPv4Address g_server;
private __gshared bool        g_haveServer = false;

public bool ntpHaveServer() { return g_haveServer; }

/// Resolve `host` and remember it. Call from the boot network probe, where DNS is known good.
public bool ntpResolveServer(const(char)* host, uint dnsTimeoutMs) {
    IPv4Address a;
    if (!dnsResolve(host, &a, dnsTimeoutMs)) {
        klog("[ntp] DNS lookup failed for "); klog(host); klog("\n");
        return false;
    }
    g_server = a;
    g_haveServer = true;
    klog("[ntp] server "); klog(host); klog(" -> ");
    klog_dec(a.bytes[0]); klog("."); klog_dec(a.bytes[1]); klog(".");
    klog_dec(a.bytes[2]); klog("."); klog_dec(a.bytes[3]); klog("\n");
    return true;
}

/// Send one SNTP request to the address ntpResolveServer() found.  Non-blocking: the reply
/// arrives asynchronously via ntpOnPacket.
public bool ntpRequest() {
    if (!g_haveServer) return false;
    IPv4Address server = g_server;

    if (g_sock < 0) {
        g_sock = udpSocket();
        if (g_sock < 0) { klog("[ntp] no UDP socket available\n"); return false; }
        if (!udpBind(g_sock, NTP_LOCALPORT)) {
            klog("[ntp] bind to local port failed\n");
            udpClose(g_sock); g_sock = -1; return false;
        }
        udpSetCallback(g_sock, &ntpOnPacket);
    }

    // A client request is 48 zero bytes apart from the first: LI=0, VN=4, Mode=3 (client).
    // Servers ignore every other field in a client packet, so leaving them zero is correct
    // rather than lazy.
    ubyte[48] pkt = 0;
    pkt[0] = 0x23;

    if (!udpSend(g_sock, server, NTP_PORT, pkt.ptr, pkt.length)) {
        klog("[ntp] send failed\n");
        return false;
    }
    klog("[ntp] request sent to ");
    klog_dec(server.bytes[0]); klog("."); klog_dec(server.bytes[1]); klog(".");
    klog_dec(server.bytes[2]); klog("."); klog_dec(server.bytes[3]); klog("\n");
    return true;
}

/// True once a request has been sent and is awaiting its reply.
public bool ntpAwaitingReply() { return g_sock >= 0 && !g_replySeen; }

/// Allow a later attempt after a failed or lost exchange.
public void ntpResetForRetry() { g_replySeen = false; }
