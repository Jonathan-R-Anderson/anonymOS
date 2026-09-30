module network.tcp;

// TCP for the in-kernel IPv4 stack.
//
// This replaced a skeleton that could open a connection and little else: it never retransmitted,
// took any sequence number as the next in-order byte, never reused a connection slot or picked an
// ephemeral port, and its receive call was a stub that returned 0.  Userspace AF_INET SOCK_STREAM
// (core/syscalls/posix.d) is built on this, so it has to be a TCP a real server will talk to:
//
//   * connections live in a fixed table and are reused; a closed connection is freed once its owner
//     (a socket fd or a kernel client) has let go and the teardown handshake is over;
//   * each connection has a transmit ring (unacknowledged + unsent bytes) and a receive ring; the
//     window we advertise is the free space in the receive ring, so a slow reader throttles the
//     sender instead of losing data;
//   * segments are cut to the peer's MSS (option on the SYN) and to the peer's advertised window;
//   * loss recovery is go-back-N from the oldest unacknowledged byte, driven by a retransmission
//     timer with exponential backoff and by three duplicate ACKs (fast retransmit);
//   * out-of-order segments are dropped and answered with a duplicate ACK -- the sender's
//     retransmission fills the hole.  No SACK, no window scaling, no timestamps: fine for the
//     package downloads and API calls this carries;
//   * FIN / RST / TIME_WAIT per RFC 793, checksums verified on input, ISNs from the TSC.
//
// Everything runs with the big kernel lock held: the RX path from the timer tick
// (networkStackPoll), the timers from tcpTick(), and the socket calls from syscalls.  Nothing here
// blocks: a caller that has to wait gets -EAGAIN and the syscall layer parks the task.

import network.types;
import network.ipv4;
import network.vnet : g_netIf;

enum int    TCP_MAX_CONN    = 32;
enum size_t TCP_RXBUF       = 65536;       // power of two
enum size_t TCP_TXBUF       = 32768;       // power of two
enum ushort TCP_MSS_OURS    = 1460;        // 1500 MTU - 20 IP - 20 TCP
enum ushort TCP_MSS_DEFAULT = 536;         // RFC 1122, until the peer says otherwise
enum uint   TCP_RTO_INIT    = 1000;
enum uint   TCP_RTO_MAX     = 16000;
enum uint   TCP_SYN_RETRIES = 5;
enum uint   TCP_DATA_RETRIES= 8;
enum uint   TCP_TIMEWAIT_MS = 2000;        // short 2MSL: nothing here reuses a 4-tuple quickly
enum int    TCP_ACCEPT_Q    = 8;

private enum : ubyte { F_FIN = 0x01, F_SYN = 0x02, F_RST = 0x04, F_PSH = 0x08, F_ACK = 0x10 }

// errno values reported to the socket layer (positive here; the caller negates).
enum int TCP_ECONNREFUSED = 111, TCP_ECONNRESET = 104, TCP_ETIMEDOUT = 110,
         TCP_EPIPE = 32, TCP_EAGAIN = 11, TCP_ENOTCONN = 107, TCP_EADDRINUSE = 98,
         TCP_ENETUNREACH = 101, TCP_EINVAL = 22;

/// Legacy callback types (the kernel's own HTTP client, network/http.d).
alias TCPConnectCallback = extern(C) void function(int) @nogc nothrow;
alias TCPDataCallback = extern(C) void function(int, const(ubyte)*, size_t) @nogc nothrow;
alias TCPCloseCallback = extern(C) void function(int) @nogc nothrow;
alias TCPAcceptCallback = extern(C) void function(int, int, const ref IPv4Address, ushort) @nogc nothrow;

private struct TcpConn {
    bool        used;
    bool        owned;       // a socket fd / kernel client still holds it
    bool        started;     // a connect or listen was issued (distinguishes "never" from "died")
    TCPState    st;
    IPv4Address rip;
    ushort      lport, rport;
    int         nif;         // network/vnet.d interface (0 = the host NIC; > 0 = a domain's interface)

    // send side
    uint   iss, sndUna, sndNxt, sndWnd;
    uint   sndMax;           // highest sequence number sent (go-back-N rewinds sndNxt, not this)
    ushort mss;
    size_t txHead, txLen;    // ring bytes; byte k has sequence number sndUna + k (SYN is acked by then)
    bool   finPending;       // no more writes: FIN follows the queued data
    bool   finSent;          // FIN transmitted (cleared by go-back-N so it is sent again)
    bool   finOnWire;        // FIN was sent at least once (its state transition happened)
    uint   finSeq;
    uint   dupAcks;

    // receive side
    uint   irs, rcvNxt;
    size_t rxHead, rxLen;
    uint   advWnd;           // window in our last segment
    bool   peerFin;

    // timers (g_tcpNow milliseconds)
    ulong  rtoAt;            // 0 = no retransmission timer
    uint   rto, retries;
    ulong  twUntil;

    int    err;              // sticky error for the owner (TCP_E*), 0 = none
    bool   errReported;      // SO_ERROR consumed it (reads/writes still see it)

    // listening sockets: established children waiting for accept()
    int    parent;
    int    backlog;
    int[TCP_ACCEPT_Q] acceptQ;
    int    aqHead, aqLen;

    TCPConnectCallback onConnect;
    TCPDataCallback    onData;
    TCPCloseCallback   onClose;
    TCPAcceptCallback  onAccept;

    ubyte[TCP_TXBUF] tx;
    ubyte[TCP_RXBUF] rx;
}

private __gshared TcpConn[TCP_MAX_CONN] g_tcp;
private __gshared ulong  g_tcpNow = 1;          // advanced by tcpTick(); never 0 (0 = "timer off")
private __gshared ushort g_tcpNextEphemeral = 49152;
private __gshared uint   g_tcpIsnBump;

// counters for the boot log / diagnostics
__gshared ulong g_tcpSegsIn, g_tcpSegsOut, g_tcpRetransmits, g_tcpBadCsum, g_tcpResetsSent;
__gshared ulong g_tcpOoo, g_tcpDupData, g_tcpZeroWnd, g_tcpWndUpd, g_tcpOverrun;
private __gshared ulong g_tcpNextDump;
private __gshared uint  g_tcpDumpN;

// ── helpers ────────────────────────────────────────────────────────────────────────────────────

private bool seqLT(uint a, uint b) @nogc nothrow { return cast(int)(a - b) < 0; }
private bool seqLE(uint a, uint b) @nogc nothrow { return cast(int)(a - b) <= 0; }
private bool seqGT(uint a, uint b) @nogc nothrow { return cast(int)(a - b) > 0; }

private ulong tcpRdtsc() @nogc nothrow {
    uint lo, hi;
    asm @nogc nothrow { rdtsc; mov lo, EAX; mov hi, EDX; }
    return (cast(ulong)hi << 32) | lo;
}

private uint tcpNewIss() @nogc nothrow {
    const ulong t = tcpRdtsc();
    g_tcpIsnBump += 64_000;
    return cast(uint)(t ^ (t >> 29)) + g_tcpIsnBump;
}

private bool validId(int id) @nogc nothrow { return id >= 0 && id < TCP_MAX_CONN && g_tcp[id].used; }

// Connection lifecycle on the serial log (bounded: a busy system must not flood the UART).
private __gshared uint g_tcpLogN;
private void tcpLog(const(char)* what, int id) @nogc nothrow {
    import core.io : klog, klog_dec;
    if (g_tcpLogN >= 80 || id < 0 || id >= TCP_MAX_CONN) return;
    ++g_tcpLogN;
    auto c = &g_tcp[id];
    klog("[tcp] "); klog(what); klog(" #"); klog_dec(cast(ulong)id);
    klog(" "); klog_dec(c.rip.bytes[0]); klog("."); klog_dec(c.rip.bytes[1]); klog(".");
    klog_dec(c.rip.bytes[2]); klog("."); klog_dec(c.rip.bytes[3]);
    klog(":"); klog_dec(c.rport); klog(" lport="); klog_dec(c.lport);
    klog(" in="); klog_dec(g_tcpSegsIn); klog(" out="); klog_dec(g_tcpSegsOut);
    klog(" rexmit="); klog_dec(g_tcpRetransmits); klog("\n");
}

// Internet checksum over the IPv4 pseudo-header + segment, as a HOST-order value.
private ushort tcpCsum(const ref IPv4Address src, const ref IPv4Address dst,
                       const(ubyte)* seg, size_t len) @nogc nothrow {
    uint sum = 0;
    sum += (cast(uint)src.bytes[0] << 8) | src.bytes[1];
    sum += (cast(uint)src.bytes[2] << 8) | src.bytes[3];
    sum += (cast(uint)dst.bytes[0] << 8) | dst.bytes[1];
    sum += (cast(uint)dst.bytes[2] << 8) | dst.bytes[3];
    sum += IPProtocol.TCP;
    sum += cast(uint)len;
    size_t i = 0;
    for (; i + 1 < len; i += 2) sum += (cast(uint)seg[i] << 8) | seg[i + 1];
    if (len & 1) sum += cast(uint)seg[len - 1] << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return cast(ushort)~sum;
}

private uint rxFree(ref TcpConn c) @nogc nothrow { return cast(uint)(TCP_RXBUF - c.rxLen); }
private uint curWindow(ref TcpConn c) @nogc nothrow {
    const uint w = rxFree(c);
    return w > 65535 ? 65535 : w;
}

private void put16(ubyte* p, uint v) @nogc nothrow { p[0] = cast(ubyte)(v >> 8); p[1] = cast(ubyte)v; }
private void put32(ubyte* p, uint v) @nogc nothrow {
    p[0] = cast(ubyte)(v >> 24); p[1] = cast(ubyte)(v >> 16); p[2] = cast(ubyte)(v >> 8); p[3] = cast(ubyte)v;
}
private uint get16(const(ubyte)* p) @nogc nothrow { return (cast(uint)p[0] << 8) | p[1]; }
private uint get32(const(ubyte)* p) @nogc nothrow {
    return (cast(uint)p[0] << 24) | (cast(uint)p[1] << 16) | (cast(uint)p[2] << 8) | p[3];
}

// Build and send one segment.  Payload comes from the transmit ring (ringOff bytes past sndUna's
// slot) when fromRing, else from `data`.
private bool sendSeg(ref TcpConn c, uint seq, ubyte flags, bool fromRing, size_t ringOff,
                     const(ubyte)* data, size_t len) @nogc nothrow {
    ubyte[1480] pkt = void;                 // 1500 MTU - 20 IP header
    const bool mssOpt = (flags & F_SYN) != 0;
    const size_t hlen = mssOpt ? 24 : 20;
    if (hlen + len > pkt.length) return false;
    put16(pkt.ptr + 0, c.lport);
    put16(pkt.ptr + 2, c.rport);
    put32(pkt.ptr + 4, seq);
    put32(pkt.ptr + 8, (flags & F_ACK) ? c.rcvNxt : 0);
    pkt[12] = cast(ubyte)((hlen / 4) << 4);
    pkt[13] = flags;
    const uint wnd = curWindow(c);
    if (wnd == 0) ++g_tcpZeroWnd;
    put16(pkt.ptr + 14, wnd);
    pkt[16] = 0; pkt[17] = 0;               // checksum
    pkt[18] = 0; pkt[19] = 0;               // urgent pointer
    if (mssOpt) { pkt[20] = 2; pkt[21] = 4; put16(pkt.ptr + 22, TCP_MSS_OURS); }
    ubyte* pl = pkt.ptr + hlen;
    if (fromRing) {
        size_t pos = (c.txHead + ringOff) & (TCP_TXBUF - 1);
        foreach (i; 0 .. len) { pl[i] = c.tx[pos]; pos = (pos + 1) & (TCP_TXBUF - 1); }
    } else if (data !is null) {
        foreach (i; 0 .. len) pl[i] = data[i];
    }
    const int prevIf = g_netIf;
    g_netIf = c.nif;                        // the connection's interface (timers send outside any RX)
    IPv4Address me; getLocalIP(&me);
    put16(pkt.ptr + 16, tcpCsum(me, c.rip, pkt.ptr, hlen + len));
    if (flags & F_ACK) c.advWnd = wnd;
    ++g_tcpSegsOut;
    const bool sent = ipv4Send(c.rip, IPProtocol.TCP, pkt.ptr, hlen + len);
    g_netIf = prevIf;
    return sent;
}

private void sendAck(ref TcpConn c) @nogc nothrow { sendSeg(c, c.sndNxt, F_ACK, false, 0, null, 0); }

// A reset for a segment that has no connection (or is unacceptable in SYN_SENT).
private void sendResetFor(const ref IPv4Address to, ushort sport, ushort dport, uint seq, uint ack,
                          ubyte inFlags, size_t segLen) @nogc nothrow {
    ubyte[20] pkt = 0;
    put16(pkt.ptr + 0, dport);                 // our port is their destination
    put16(pkt.ptr + 2, sport);
    ubyte flags;
    if (inFlags & F_ACK) {
        put32(pkt.ptr + 4, ack);
        flags = F_RST;
    } else {
        uint a = seq + cast(uint)segLen;
        if (inFlags & F_SYN) ++a;
        if (inFlags & F_FIN) ++a;
        put32(pkt.ptr + 8, a);
        flags = F_RST | F_ACK;
    }
    pkt[12] = 5 << 4;
    pkt[13] = flags;
    IPv4Address me; getLocalIP(&me);
    put16(pkt.ptr + 16, tcpCsum(me, to, pkt.ptr, 20));
    ++g_tcpResetsSent; ++g_tcpSegsOut;
    ipv4Send(to, IPProtocol.TCP, pkt.ptr, 20);
}

private void sendReset(ref TcpConn c) @nogc nothrow {
    sendSeg(c, c.sndNxt, F_RST | F_ACK, false, 0, null, 0);
    ++g_tcpResetsSent;
}

private void freeConn(int id) @nogc nothrow {
    auto c = &g_tcp[id];
    c.used = false;
    c.owned = false;
    c.st = TCPState.CLOSED;
    c.rtoAt = 0;
}

// The connection is over (reset, timed out, or fully closed).  Free it unless an owner still has
// to observe the end (EOF / the error); the owner's release frees it then.
private void finish(int id, int err) @nogc nothrow {
    auto c = &g_tcp[id];
    tcpLog(err == TCP_ECONNREFUSED ? "refused" : err == TCP_ECONNRESET ? "reset" :
           err == TCP_ETIMEDOUT ? "timed out" : "closed", id);
    if (err != 0 && c.err == 0) c.err = err;
    c.st = TCPState.CLOSED;
    c.rtoAt = 0;
    if (c.onClose !is null) { auto cb = c.onClose; c.onClose = null; cb(id); }
    if (!c.owned) {
        // an unaccepted child of a listener: drop it from the accept queue too
        if (c.parent >= 0) unqueueChild(c.parent, id);
        freeConn(id);
    }
}

private void unqueueChild(int parent, int child) @nogc nothrow {
    if (!validId(parent)) return;
    auto p = &g_tcp[parent];
    int[TCP_ACCEPT_Q] keep; int n = 0;
    foreach (k; 0 .. p.aqLen) {
        const int x = p.acceptQ[(p.aqHead + k) % TCP_ACCEPT_Q];
        if (x != child) keep[n++] = x;
    }
    foreach (k; 0 .. n) p.acceptQ[k] = keep[k];
    p.aqHead = 0; p.aqLen = n;
}

// Run the retransmission timer while anything is unacknowledged -- or, as the persist timer, while
// data waits on a zero window (the window update that would restart us can itself be lost).
private void armRto(ref TcpConn c) @nogc nothrow {
    if (c.sndMax != c.sndUna || (c.txLen > 0 && c.sndWnd == 0)) { if (c.rtoAt == 0) c.rtoAt = g_tcpNow + c.rto; }
    else c.rtoAt = 0;
}

private void noteSent(ref TcpConn c) @nogc nothrow { if (seqGT(c.sndNxt, c.sndMax)) c.sndMax = c.sndNxt; }

// Send whatever the window allows: queued data, then the FIN.  `probe` forces one byte into a
// zero window (the retransmission timer's persist probe).
private void output(int id, bool probe) @nogc nothrow {
    auto c = &g_tcp[id];
    switch (c.st) {
        case TCPState.ESTABLISHED, TCPState.CLOSE_WAIT, TCPState.FIN_WAIT_1,
             TCPState.CLOSING, TCPState.LAST_ACK:
            break;
        default:
            return;
    }
    if (c.finSent) return;                        // everything, FIN included, is on the wire
    size_t off = c.sndNxt - c.sndUna;
    uint wnd = c.sndWnd;
    if (probe && wnd == 0) wnd = 1;
    while (off < c.txLen && off < wnd) {
        size_t n = c.txLen - off;
        if (n > c.mss) n = c.mss;
        if (n > wnd - off) n = wnd - off;
        if (!sendSeg(*c, c.sndUna + cast(uint)off, F_ACK | F_PSH, true, off, null, n)) break;
        off += n;
        c.sndNxt = c.sndUna + cast(uint)off;
        noteSent(*c);
    }
    if (c.finPending && !c.finSent && off == c.txLen) {
        c.finSeq = c.sndUna + cast(uint)c.txLen;
        sendSeg(*c, c.finSeq, F_FIN | F_ACK, false, 0, null, 0);
        c.finSent = true;
        c.sndNxt = c.finSeq + 1;
        noteSent(*c);
        if (!c.finOnWire) {
            c.finOnWire = true;
            if (c.st == TCPState.ESTABLISHED) c.st = TCPState.FIN_WAIT_1;
            else if (c.st == TCPState.CLOSE_WAIT) c.st = TCPState.LAST_ACK;
        }
    }
    armRto(*c);
}

private void enterTimeWait(ref TcpConn c) @nogc nothrow {
    c.st = TCPState.TIME_WAIT;
    c.rtoAt = 0;
    c.twUntil = g_tcpNow + TCP_TIMEWAIT_MS;
}

// ── input ──────────────────────────────────────────────────────────────────────────────────────

private ushort parseMss(const(ubyte)* opt, size_t olen) @nogc nothrow {
    size_t i = 0;
    while (i < olen) {
        const ubyte kind = opt[i];
        if (kind == 0) break;
        if (kind == 1) { ++i; continue; }
        if (i + 1 >= olen) break;
        const ubyte l = opt[i + 1];
        if (l < 2 || i + l > olen) break;
        if (kind == 2 && l == 4) {
            const uint m = get16(opt + i + 2);
            return cast(ushort)(m < 64 ? 64 : (m > TCP_MSS_OURS ? TCP_MSS_OURS : m));
        }
        i += l;
    }
    return TCP_MSS_DEFAULT;
}

private int allocConn() @nogc nothrow {
    foreach (i; 0 .. TCP_MAX_CONN) {
        if (g_tcp[i].used) continue;
        auto c = &g_tcp[i];
        c.used = true; c.owned = false; c.started = false;
        c.st = TCPState.CLOSED;
        c.rip = IPv4Address(0, 0, 0, 0);
        c.lport = 0; c.rport = 0; c.nif = 0;
        c.iss = 0; c.sndUna = 0; c.sndNxt = 0; c.sndMax = 0; c.sndWnd = 0; c.mss = TCP_MSS_DEFAULT;
        c.txHead = 0; c.txLen = 0;
        c.finPending = false; c.finSent = false; c.finOnWire = false; c.finSeq = 0; c.dupAcks = 0;
        c.irs = 0; c.rcvNxt = 0; c.rxHead = 0; c.rxLen = 0; c.advWnd = 0; c.peerFin = false;
        c.rtoAt = 0; c.rto = TCP_RTO_INIT; c.retries = 0; c.twUntil = 0;
        c.err = 0; c.errReported = false;
        c.parent = -1; c.backlog = 0; c.aqHead = 0; c.aqLen = 0;
        c.onConnect = null; c.onData = null; c.onClose = null; c.onAccept = null;
        return cast(int)i;
    }
    return -1;
}

/// Handle a received TCP segment (called by the IPv4 dispatcher).
export extern(C) void tcpHandlePacket(const(ubyte)* data, size_t len,
                                       const ref IPv4Address srcIP) @nogc nothrow {
    if (data is null || len < 20) return;
    const size_t doff = (data[12] >> 4) * 4;
    if (doff < 20 || doff > len) return;
    {
        IPv4Address me; getLocalIP(&me);
        if (tcpCsum(srcIP, me, data, len) != 0) { ++g_tcpBadCsum; return; }
    }
    ++g_tcpSegsIn;
    const ushort sport = cast(ushort)get16(data + 0);
    const ushort dport = cast(ushort)get16(data + 2);
    const uint   seq   = get32(data + 4);
    const uint   ack   = get32(data + 8);
    const ubyte  flags = data[13];
    const uint   win   = get16(data + 14);
    const(ubyte)* payload = data + doff;
    size_t plen = len - doff;

    int id = -1, lid = -1;
    foreach (i; 0 .. TCP_MAX_CONN) {
        auto c = &g_tcp[i];
        if (!c.used || c.lport != dport) continue;
        if (c.st == TCPState.LISTEN) { lid = cast(int)i; continue; }
        if (c.st == TCPState.CLOSED) continue;
        if (c.rport == sport && c.rip.isEqual(srcIP) && c.nif == g_netIf) { id = cast(int)i; break; }
    }

    if (id < 0) {
        if (lid >= 0 && (flags & F_SYN) && !(flags & (F_ACK | F_RST))) {
            listenerSyn(lid, srcIP, sport, dport, seq, win, data + 20, doff - 20);
            return;
        }
        if (!(flags & F_RST)) sendResetFor(srcIP, sport, dport, seq, ack, flags, plen);
        return;
    }

    auto c = &g_tcp[id];

    // ── SYN_SENT ──
    if (c.st == TCPState.SYN_SENT) {
        if ((flags & F_ACK) && ack != c.iss + 1) {
            if (!(flags & F_RST)) sendResetFor(srcIP, sport, dport, seq, ack, flags, plen);
            return;
        }
        if (flags & F_RST) {
            if (flags & F_ACK) finish(id, TCP_ECONNREFUSED);
            return;
        }
        if ((flags & F_SYN) && (flags & F_ACK)) {
            c.irs = seq; c.rcvNxt = seq + 1;
            c.sndUna = ack; c.sndNxt = ack; c.sndMax = ack;
            c.sndWnd = win;
            c.mss = parseMss(data + 20, doff - 20);
            c.st = TCPState.ESTABLISHED;
            c.retries = 0; c.rto = TCP_RTO_INIT; c.rtoAt = 0;
            tcpLog("established", id);
            sendAck(*c);
            if (c.onConnect !is null) c.onConnect(id);
            output(id, false);
        }
        return;
    }

    // ── synchronized states ──
    if (flags & F_RST) {
        // Accept a reset only if it falls in the receive window (RFC 793; a blind reset is ignored).
        const uint w = curWindow(*c) ? curWindow(*c) : 1;
        if (seqLE(c.rcvNxt, seq) && seqLT(seq, c.rcvNxt + w)) {
            const bool closing = c.st == TCPState.TIME_WAIT || c.st == TCPState.LAST_ACK
                              || c.st == TCPState.CLOSING;
            finish(id, closing ? 0 : TCP_ECONNRESET);
        }
        return;
    }
    if (flags & F_SYN) {
        // A retransmitted SYN for a connection we already answered: answer again.  Anything else
        // is a challenge-ACK case; the ACK tells the peer where we are.
        if (c.st == TCPState.SYN_RECEIVED && seq == c.irs) {
            sendSeg(*c, c.iss, F_SYN | F_ACK, false, 0, null, 0);
            return;
        }
        sendAck(*c);
        return;
    }
    if (!(flags & F_ACK)) return;

    if (c.st == TCPState.SYN_RECEIVED) {
        if (ack != c.iss + 1) { sendResetFor(srcIP, sport, dport, seq, ack, flags, plen); return; }
        c.sndUna = ack; c.sndNxt = ack; c.sndMax = ack; c.sndWnd = win;
        c.st = TCPState.ESTABLISHED;
        c.retries = 0; c.rto = TCP_RTO_INIT; c.rtoAt = 0;
        if (c.parent >= 0 && validId(c.parent) && g_tcp[c.parent].st == TCPState.LISTEN) {
            auto p = &g_tcp[c.parent];
            if (p.aqLen < TCP_ACCEPT_Q) {
                p.acceptQ[(p.aqHead + p.aqLen) % TCP_ACCEPT_Q] = id;
                ++p.aqLen;
                if (p.onAccept !is null) p.onAccept(c.parent, id, c.rip, c.rport);
            } else { sendReset(*c); finish(id, TCP_ECONNRESET); return; }
        }
    }

    // ── ACK processing ──
    bool finAcked = false;
    if (seqGT(ack, c.sndUna) && seqLE(ack, c.sndMax)) {
        uint acked = ack - c.sndUna;
        if (c.finSent && seqGT(ack, c.finSeq)) { finAcked = true; --acked; }
        size_t dataAck = acked;
        if (dataAck > c.txLen) dataAck = c.txLen;
        c.txHead = (c.txHead + dataAck) & (TCP_TXBUF - 1);
        c.txLen -= dataAck;
        c.sndUna = ack;
        if (seqLT(c.sndNxt, ack)) c.sndNxt = ack;      // a rewound sender skips what arrived anyway
        c.retries = 0; c.dupAcks = 0; c.rto = TCP_RTO_INIT;
        c.rtoAt = 0;
        armRto(*c);
    } else if (ack == c.sndUna && plen == 0 && !(flags & F_FIN) && c.sndMax != c.sndUna
               && win == c.sndWnd) {
        if (++c.dupAcks == 3) {                   // fast retransmit: go back to the hole
            ++g_tcpRetransmits;
            c.sndNxt = c.sndUna;
            c.finSent = false;
            c.rtoAt = 0;
        }
    }
    if (seqLE(c.sndUna, ack)) c.sndWnd = win;
    if (c.finOnWire && seqGT(c.sndUna, c.finSeq)) finAcked = true;

    if (finAcked) {
        if (c.st == TCPState.FIN_WAIT_1) c.st = TCPState.FIN_WAIT_2;
        else if (c.st == TCPState.CLOSING) enterTimeWait(*c);
        else if (c.st == TCPState.LAST_ACK) { finish(id, 0); return; }
    }

    // ── data + FIN ──
    bool needAck = false;
    bool fin = (flags & F_FIN) != 0;
    uint segSeq = seq;
    if (plen > 0 || fin) {
        if (seqLT(segSeq, c.rcvNxt)) {
            const uint dup = c.rcvNxt - segSeq;
            if (dup >= plen + (fin ? 1 : 0)) { ++g_tcpDupData; sendAck(*c); output(id, false); return; }  // all old
            if (dup <= plen) { payload += dup; plen -= dup; segSeq = c.rcvNxt; }
        }
        if (segSeq != c.rcvNxt) {                  // out of order: ask for the hole
            ++g_tcpOoo;
            sendAck(*c);
            output(id, false);
            return;
        }
        const bool takesData = c.st == TCPState.ESTABLISHED || c.st == TCPState.FIN_WAIT_1
                            || c.st == TCPState.FIN_WAIT_2;
        if (plen > 0 && takesData) {
            size_t n = plen;
            if (c.onData !is null) {
                c.onData(id, payload, n);
            } else {
                const uint room = rxFree(*c);
                if (n > room) { n = room; fin = false; ++g_tcpOverrun; }   // the sender overran our window: drop the tail
                size_t pos = (c.rxHead + c.rxLen) & (TCP_RXBUF - 1);
                foreach (i; 0 .. n) { c.rx[pos] = payload[i]; pos = (pos + 1) & (TCP_RXBUF - 1); }
                c.rxLen += n;
            }
            c.rcvNxt += cast(uint)n;
            needAck = true;
        } else if (plen > 0) {
            fin = false;                           // data after our read side closed: ignore it
        }
        if (fin) {
            c.rcvNxt += 1;
            c.peerFin = true;
            needAck = true;
            if (c.st == TCPState.ESTABLISHED) c.st = TCPState.CLOSE_WAIT;
            else if (c.st == TCPState.FIN_WAIT_1) {
                if (finAcked || (c.finOnWire && seqGT(c.sndUna, c.finSeq))) enterTimeWait(*c);
                else c.st = TCPState.CLOSING;
            } else if (c.st == TCPState.FIN_WAIT_2) enterTimeWait(*c);
            if (c.onClose !is null) { auto cb = c.onClose; c.onClose = null; cb(id); }
        }
    }
    if (needAck) sendAck(*c);
    output(id, false);
}

private void listenerSyn(int lid, const ref IPv4Address src, ushort sport, ushort dport,
                         uint seq, uint win, const(ubyte)* opt, size_t olen) @nogc nothrow {
    auto l = &g_tcp[lid];
    int pending = l.aqLen;
    foreach (i; 0 .. TCP_MAX_CONN)
        if (g_tcp[i].used && g_tcp[i].parent == lid && g_tcp[i].st == TCPState.SYN_RECEIVED) ++pending;
    if (pending >= (l.backlog > 0 ? l.backlog : 1)) return;     // full: let the peer retry
    const int cid = allocConn();
    if (cid < 0) return;
    auto c = &g_tcp[cid];
    c.started = true;
    c.parent = lid;
    c.rip = src; c.rport = sport; c.lport = dport;
    c.nif = g_netIf;                        // answered on the interface the SYN came in on
    c.irs = seq; c.rcvNxt = seq + 1;
    c.iss = tcpNewIss(); c.sndUna = c.iss; c.sndNxt = c.iss + 1; c.sndMax = c.sndNxt;
    c.sndWnd = win;
    c.mss = parseMss(opt, olen);
    c.st = TCPState.SYN_RECEIVED;
    c.onConnect = l.onConnect; c.onData = l.onData; c.onClose = l.onClose;
    sendSeg(*c, c.iss, F_SYN | F_ACK, false, 0, null, 0);
    c.rtoAt = g_tcpNow + c.rto;
}

// ── timers ─────────────────────────────────────────────────────────────────────────────────────

/// Drive retransmission and TIME_WAIT; call from the kernel tick with a monotonic millisecond clock.
export extern(C) void tcpTick(ulong nowMs) @nogc nothrow {
    g_tcpNow = nowMs ? nowMs : 1;
    if (g_tcpNow >= g_tcpNextDump) { g_tcpNextDump = g_tcpNow + 5000; tcpDump(); }
    foreach (i; 0 .. TCP_MAX_CONN) {
        auto c = &g_tcp[i];
        if (!c.used) continue;
        const int id = cast(int)i;
        if (c.st == TCPState.TIME_WAIT) {
            if (g_tcpNow >= c.twUntil) finish(id, 0);
            continue;
        }
        if (c.rtoAt == 0 || g_tcpNow < c.rtoAt) continue;
        c.rtoAt = 0;
        ++c.retries;
        ++g_tcpRetransmits;
        if (c.retries <= 2) tcpLog("retransmit", id);
        c.rto = c.rto * 2 > TCP_RTO_MAX ? TCP_RTO_MAX : c.rto * 2;
        if (c.st == TCPState.SYN_SENT || c.st == TCPState.SYN_RECEIVED) {
            if (c.retries > TCP_SYN_RETRIES) { finish(id, TCP_ETIMEDOUT); continue; }
            sendSeg(*c, c.iss, c.st == TCPState.SYN_SENT ? F_SYN : cast(ubyte)(F_SYN | F_ACK),
                    false, 0, null, 0);
            c.rtoAt = g_tcpNow + c.rto;
            continue;
        }
        if (c.retries > TCP_DATA_RETRIES) { sendReset(*c); finish(id, TCP_ETIMEDOUT); continue; }
        // go-back-N from the oldest unacknowledged byte (a zero window gets a one-byte probe)
        c.sndNxt = c.sndUna;
        c.finSent = false;
        output(id, true);
        if (c.rtoAt == 0 && c.txLen > 0) c.rtoAt = g_tcpNow + c.rto;   // keep probing a shut window
    }
}

// Every 5 s while any connection is open (bounded): each connection's state, so a stalled transfer
// shows WHICH side is waiting -- our window, their data, or a hole we keep asking for.
private void tcpDump() @nogc nothrow {
    import core.io : klog, klog_dec;
    if (g_tcpDumpN >= 60) return;
    bool any = false;
    foreach (i; 0 .. TCP_MAX_CONN) {
        auto c = &g_tcp[i];
        if (!c.used || c.st == TCPState.CLOSED || c.st == TCPState.LISTEN) continue;
        if (!any) {
            any = true; ++g_tcpDumpN;
            klog("[tcp] stats in="); klog_dec(g_tcpSegsIn); klog(" out="); klog_dec(g_tcpSegsOut);
            klog(" ooo="); klog_dec(g_tcpOoo); klog(" dup="); klog_dec(g_tcpDupData);
            klog(" zerownd="); klog_dec(g_tcpZeroWnd); klog(" wndupd="); klog_dec(g_tcpWndUpd);
            klog(" overrun="); klog_dec(g_tcpOverrun); klog(" rexmit="); klog_dec(g_tcpRetransmits);
            klog(" badcsum="); klog_dec(g_tcpBadCsum); klog("\n");
        }
        klog("[tcp]   #"); klog_dec(i); klog(" st="); klog_dec(cast(ulong)c.st);
        klog(" rx="); klog_dec(c.rxLen); klog(" adv="); klog_dec(c.advWnd);
        klog(" rcvNxt="); klog_dec(c.rcvNxt - c.irs); klog(" tx="); klog_dec(c.txLen);
        klog(" una="); klog_dec(c.sndUna - c.iss); klog(" max="); klog_dec(c.sndMax - c.iss);
        klog(" swnd="); klog_dec(c.sndWnd); klog(" fin="); klog_dec(c.peerFin ? 1 : 0);
        klog(" owned="); klog_dec(c.owned ? 1 : 0); klog("\n");
    }
}

// ── socket-layer API (core/syscalls/posix.d) ────────────────────────────────────────────────────

/// A new, unconnected connection owned by the caller; -1 when the table is full.
export extern(C) int tcpAlloc() @nogc nothrow {
    const int id = allocConn();
    if (id >= 0) g_tcp[id].owned = true;
    return id;
}

private bool portInUse(ushort port) @nogc nothrow {
    foreach (ref c; g_tcp)
        if (c.used && c.lport == port && (c.owned || c.st != TCPState.CLOSED)) return true;
    return false;
}

/// An unused local port from the dynamic range (0 if none).
export extern(C) ushort tcpEphemeral() @nogc nothrow {
    foreach (k; 0 .. 16384) {
        const ushort p = g_tcpNextEphemeral;
        g_tcpNextEphemeral = cast(ushort)(p >= 65535 ? 49152 : p + 1);
        if (!portInUse(p)) return p;
    }
    return 0;
}

export extern(C) int tcpBindPort(int id, ushort port) @nogc nothrow {
    if (!validId(id)) return -TCP_EINVAL;
    if (port == 0) port = tcpEphemeral();
    if (port == 0 || portInUse(port)) return -TCP_EADDRINUSE;
    g_tcp[id].lport = port;
    return port;
}

export extern(C) ushort tcpLocalPort(int id) @nogc nothrow { return validId(id) ? g_tcp[id].lport : 0; }

/// Send the SYN.  Completion (or failure) shows up through tcpIsConnected / tcpError.
export extern(C) int tcpConnectStart(int id, IPv4Address ip, ushort port) @nogc nothrow {
    if (!validId(id)) return -TCP_EINVAL;
    auto c = &g_tcp[id];
    if (c.started) return -TCP_EINVAL;
    IPv4Address me; getLocalIP(&me);
    if (me.addr == 0) return -TCP_ENETUNREACH;
    if (c.lport == 0) { const int p = tcpBindPort(id, 0); if (p < 0) return p; }
    c.started = true;
    c.rip = ip; c.rport = port;
    c.nif = g_netIf;                        // the caller selected the route (posix inetTcpConnect)
    c.iss = tcpNewIss(); c.sndUna = c.iss; c.sndNxt = c.iss + 1; c.sndMax = c.sndNxt;
    c.st = TCPState.SYN_SENT;
    c.rto = TCP_RTO_INIT; c.retries = 0;
    tcpLog("connect", id);
    sendSeg(*c, c.iss, F_SYN, false, 0, null, 0);   // an ARP miss just means the timer resends it
    c.rtoAt = g_tcpNow + c.rto;
    return 0;
}

export extern(C) int tcpListenOn(int id, int backlog) @nogc nothrow {
    if (!validId(id)) return -TCP_EINVAL;
    auto c = &g_tcp[id];
    if (c.started && c.st != TCPState.LISTEN) return -TCP_EINVAL;
    if (c.lport == 0) { const int p = tcpBindPort(id, 0); if (p < 0) return p; }
    c.started = true;
    c.st = TCPState.LISTEN;
    c.backlog = backlog < 1 ? 1 : (backlog > TCP_ACCEPT_Q ? TCP_ACCEPT_Q : backlog);
    return 0;
}

/// An established connection from the listener's queue (now owned by the caller), or -1.
export extern(C) int tcpAcceptPop(int id) @nogc nothrow {
    if (!validId(id)) return -1;
    auto l = &g_tcp[id];
    while (l.aqLen > 0) {
        const int cid = l.acceptQ[l.aqHead];
        l.aqHead = (l.aqHead + 1) % TCP_ACCEPT_Q;
        --l.aqLen;
        if (!validId(cid)) continue;
        g_tcp[cid].owned = true;
        g_tcp[cid].parent = -1;
        return cid;
    }
    return -1;
}

/// Bytes read (>0), 0 at end of stream, or -errno (-EAGAIN: nothing yet).
export extern(C) long tcpRead(int id, ubyte* buf, size_t len) @nogc nothrow {
    if (!validId(id)) return -TCP_EINVAL;
    auto c = &g_tcp[id];
    if (c.rxLen > 0) {
        if (len == 0) return 0;
        size_t n = c.rxLen < len ? c.rxLen : len;
        foreach (i; 0 .. n) { buf[i] = c.rx[c.rxHead]; c.rxHead = (c.rxHead + 1) & (TCP_RXBUF - 1); }
        c.rxLen -= n;
        // Reopen the window the peer is waiting on (it may be sitting on a zero window).
        const uint w = curWindow(*c);
        if (c.st != TCPState.CLOSED && c.st != TCPState.TIME_WAIT && c.st != TCPState.LISTEN &&
            (w >= c.advWnd + 2 * c.mss || (c.advWnd < c.mss && w >= c.mss))) {
            ++g_tcpWndUpd;
            sendAck(*c);
        }
        return cast(long)n;
    }
    if (c.peerFin) return 0;
    if (c.err != 0) return -c.err;
    if (!c.started) return -TCP_ENOTCONN;
    if (c.st == TCPState.CLOSED || c.st == TCPState.TIME_WAIT) return 0;
    return -TCP_EAGAIN;
}

/// Bytes queued (>0) or -errno (-EAGAIN: the send ring is full or the handshake is still running).
export extern(C) long tcpWrite(int id, const(ubyte)* buf, size_t len) @nogc nothrow {
    if (!validId(id)) return -TCP_EINVAL;
    auto c = &g_tcp[id];
    if (c.err != 0) return -c.err;
    if (c.st == TCPState.SYN_SENT || c.st == TCPState.SYN_RECEIVED) return -TCP_EAGAIN;
    if (!c.started) return -TCP_ENOTCONN;
    if ((c.st != TCPState.ESTABLISHED && c.st != TCPState.CLOSE_WAIT) || c.finPending) return -TCP_EPIPE;
    if (len == 0) return 0;
    const size_t room = TCP_TXBUF - c.txLen;
    if (room == 0) return -TCP_EAGAIN;
    const size_t n = len < room ? len : room;
    size_t pos = (c.txHead + c.txLen) & (TCP_TXBUF - 1);
    foreach (i; 0 .. n) { c.tx[pos] = buf[i]; pos = (pos + 1) & (TCP_TXBUF - 1); }
    c.txLen += n;
    output(id, false);
    return cast(long)n;
}

/// shutdown(SHUT_WR): the FIN follows whatever is still queued.
export extern(C) void tcpShutdownWr(int id) @nogc nothrow {
    if (!validId(id)) return;
    auto c = &g_tcp[id];
    if (c.st == TCPState.ESTABLISHED || c.st == TCPState.CLOSE_WAIT) {
        c.finPending = true;
        output(id, false);
    }
}

/// The owner is done with it (socket fd closed).  An open connection closes gracefully in the
/// background and frees itself; anything else is freed now.
export extern(C) void tcpRelease(int id) @nogc nothrow {
    if (!validId(id)) return;
    auto c = &g_tcp[id];
    c.owned = false;
    c.onConnect = null; c.onData = null; c.onClose = null; c.onAccept = null;
    switch (c.st) {
        case TCPState.ESTABLISHED, TCPState.CLOSE_WAIT:
            c.finPending = true;
            output(id, false);
            return;
        case TCPState.FIN_WAIT_1, TCPState.FIN_WAIT_2, TCPState.CLOSING, TCPState.LAST_ACK,
             TCPState.TIME_WAIT:
            return;                                  // teardown already running
        case TCPState.LISTEN:
            // reset and free every child that was never accepted
            foreach (i; 0 .. TCP_MAX_CONN) {
                auto k = &g_tcp[i];
                if (k.used && k.parent == id && !k.owned) { sendReset(*k); freeConn(cast(int)i); }
            }
            freeConn(id);
            return;
        case TCPState.SYN_SENT, TCPState.SYN_RECEIVED:
            sendReset(*c);
            freeConn(id);
            return;
        default:
            freeConn(id);
            return;
    }
}

export extern(C) bool tcpIsListening(int id) @nogc nothrow { return validId(id) && g_tcp[id].st == TCPState.LISTEN; }
export extern(C) bool tcpIsConnecting(int id) @nogc nothrow {
    return validId(id) && (g_tcp[id].st == TCPState.SYN_SENT || g_tcp[id].st == TCPState.SYN_RECEIVED);
}
export extern(C) bool tcpIsConnected(int id) @nogc nothrow {
    if (!validId(id)) return false;
    const st = g_tcp[id].st;
    return st != TCPState.CLOSED && st != TCPState.LISTEN && st != TCPState.SYN_SENT
        && st != TCPState.SYN_RECEIVED;
}

/// Readable for poll(): data, end of stream, an error, or (listener) a connection to accept.
export extern(C) bool tcpReadable(int id) @nogc nothrow {
    if (!validId(id)) return true;
    auto c = &g_tcp[id];
    if (c.st == TCPState.LISTEN) return c.aqLen > 0;
    if (c.rxLen > 0 || c.peerFin || c.err != 0) return true;
    return c.started && (c.st == TCPState.CLOSED || c.st == TCPState.TIME_WAIT);
}

/// Changes whenever input arrives on the connection (a byte, a FIN, an error, a queued accept) --
/// the edge counter for an edge-triggered (EPOLLET) epoll watch.
export extern(C) ulong tcpEventGen(int id) @nogc nothrow {
    if (!validId(id)) return 0;
    auto c = &g_tcp[id];
    return (cast(ulong)c.rcvNxt << 16) ^ (cast(ulong)c.aqLen << 4) ^ (c.peerFin ? 2 : 0) ^ (c.err != 0 ? 1 : 0)
         ^ (cast(ulong)c.st << 8);
}

/// Writable for poll(): room in the send ring on a connected socket, or a result to report
/// (a finished or failed connect -- the non-blocking connect's POLLOUT).
export extern(C) bool tcpWritable(int id) @nogc nothrow {
    if (!validId(id)) return true;
    auto c = &g_tcp[id];
    if (c.err != 0) return true;
    if (c.st == TCPState.ESTABLISHED || c.st == TCPState.CLOSE_WAIT)
        return !c.finPending && c.txLen < TCP_TXBUF;
    return c.started && c.st == TCPState.CLOSED;
}

/// The pending error (TCP_E*), 0 if none; `consume` clears it for SO_ERROR semantics.
export extern(C) int tcpError(int id, bool consume) @nogc nothrow {
    if (!validId(id)) return 0;
    auto c = &g_tcp[id];
    if (c.err == 0) return 0;
    if (consume) {
        if (c.errReported) return 0;
        c.errReported = true;
    }
    return c.err;
}

export extern(C) void tcpPeer(int id, IPv4Address* ip, ushort* port) @nogc nothrow {
    if (!validId(id)) return;
    if (ip !is null) *ip = g_tcp[id].rip;
    if (port !is null) *port = g_tcp[id].rport;
}

/// Connections in use (for diagnostics).
export extern(C) int tcpConnCount() @nogc nothrow {
    int n = 0;
    foreach (ref c; g_tcp) if (c.used) ++n;
    return n;
}

// ── legacy API (network/http.d, network/stack.d tcpConnectTo) ────────────────────────────────

export extern(C) int tcpSocket() @nogc nothrow { return tcpAlloc(); }

export extern(C) bool tcpBind(int sockfd, ushort port) @nogc nothrow {
    return tcpBindPort(sockfd, port) > 0;
}

export extern(C) bool tcpListen(int sockfd) @nogc nothrow { return tcpListenOn(sockfd, TCP_ACCEPT_Q) == 0; }

export extern(C) bool tcpConnect(int sockfd, const ref IPv4Address remoteIP, ushort remotePort) @nogc nothrow {
    return tcpConnectStart(sockfd, remoteIP, remotePort) == 0;
}

export extern(C) int tcpSend(int sockfd, const(ubyte)* data, size_t len) @nogc nothrow {
    if (!validId(sockfd)) return -1;
    size_t done = 0;
    while (done < len) {
        const long n = tcpWrite(sockfd, data + done, len - done);
        if (n <= 0) break;
        done += cast(size_t)n;
    }
    return done == len ? cast(int)len : (done > 0 ? cast(int)done : -1);
}

export extern(C) void tcpClose(int sockfd) @nogc nothrow { tcpRelease(sockfd); }

export extern(C) void tcpSetCallbacks(int sockfd, TCPConnectCallback onConnect, TCPDataCallback onData,
                                       TCPCloseCallback onClose, TCPAcceptCallback onAccept) @nogc nothrow {
    if (!validId(sockfd)) return;
    g_tcp[sockfd].onConnect = onConnect;
    g_tcp[sockfd].onData = onData;
    g_tcp[sockfd].onClose = onClose;
    g_tcp[sockfd].onAccept = onAccept;
}

export extern(C) int tcpReceive(int sockfd, ubyte* buffer, size_t len) @nogc nothrow {
    const long n = tcpRead(sockfd, buffer, len);
    return n > 0 ? cast(int)n : 0;
}
