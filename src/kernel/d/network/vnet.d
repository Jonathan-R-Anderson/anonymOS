/**
 * network/vnet.d -- the virtual network: TAP ports for virtual machines, layer-2 segments, the
 * uplink router (DHCP + NAT out through the host's network), and per-domain virtual interfaces,
 * so a domain's traffic can be routed THROUGH a firewall VM (or through another domain's route)
 * and back out to the internet.
 *
 *   domain "Personal" --(its interface 192.168.1.20 on segment lan-opnsense)--> OPNsense LAN
 *   OPNsense WAN --(segment "uplink", 10.77.0.0/24)--> this router 10.77.0.1 --NAT--> host NIC
 *
 * Pieces:
 *   - A PORT is a TAP (a /dev/net/tun fd a VMM's virtio-net attached to), the ROUTER, or a domain
 *     interface (DOMIF).  Ports live on SEGMENTS: plain learning switches.  A TAP's segment comes
 *     from its name: "wan*"/"nat*" join "uplink"; anything else joins the segment named by the text
 *     before the first '.', so "lan-opnsense" and "lan-opnsense.2" share a LAN.
 *   - The ROUTER is 10.77.0.1 on "uplink": it answers ARP and ping, leases 10.77.0.2.. by DHCP, and
 *     NATs everything else (TCP/UDP by port, ping by identifier) out through the host stack, with
 *     the host's address.  Inbound replies are recognised by their NAT port (vnetNatInbound(),
 *     called by the host stack before local delivery) and switched back onto the segment.
 *   - A DOMIF is a domain's own address on a LAN segment (192.168.1.20+).  The host TCP/UDP/ICMP
 *     code runs unchanged: g_netIf names the interface a packet belongs to -- getLocalIP() answers
 *     its address, ipv4Send() hands its packets here -- and a TCP connection remembers its
 *     interface.  ARP towards a VM is asynchronous (the VMM has to run), so packets to an
 *     unresolved next hop wait in a small queue flushed by the ARP reply.
 *   - ROUTES: per domain, "direct" (the host network), "vm:<segment>" (through the gateway VM on
 *     that segment, its .1), or "domain:<name>" (whatever that domain's route is -- chains resolve,
 *     loops fail closed).  Set by the Domain Manager's `route` verb.
 *
 * Offloads are off end to end: the VMM is started with offload_tso/ufo/csum=off, so every frame on
 * a segment carries finished checksums and no GSO.
 */
module network.vnet;

import network.types;
import core.io : klog, klog_hex, klog_dec;

@nogc nothrow:

enum int VNET_MAX_PORTS  = 24;       // port 0 is never used: g_netIf == 0 means "the host NIC"
enum int VNET_MAX_SEGS   = 8;
enum int VNET_QLEN       = 128;      // frames queued towards one TAP reader
enum int VNET_FRAME_MAX  = 1522;
enum int VNET_MAX_ROUTES = 32;
enum int VNET_NAT_SLOTS  = 512;
enum ushort VNET_NAT_BASE = 20000;   // host ports 20000..20511 carry NAT flows (TCP ephemerals are 49152+)

enum PortKind : ubyte { None, Tap, Router, DomIf }

/// The interface the current packet belongs to: 0 = the host NIC, else a DOMIF port index.  Set
/// around every send/receive that concerns a domain interface (the kernel is single-threaded under
/// the BKL here, so a scoped global is enough).
__gshared int g_netIf = 0;

private struct VFrame { ushort len; ubyte[VNET_FRAME_MAX] data; }

private struct VPort {
    bool     used;
    PortKind kind;
    int      seg;
    char[16] name = 0;           // char.init is 0xFF: keep it terminated
    ubyte[6] mac;
    // TAP
    VFrame*  q;
    ulong    qPhys;
    int      qHead, qLen;
    uint     vnetHdr;
    uint     tapFlags;
    int      opens;
    // L3 (router / domain interface), addresses as IPv4Address.addr (wire byte order in memory)
    uint     ip, mask, gw;
    uint     domain;                 // DOMIF: the owning domain object id
    uint[8]  arpIp;
    ubyte[6][8] arpMac;
    int      arpN;
    ulong    rx, tx, drops;
}

private struct VSeg {
    bool     used;
    char[24] name = 0;
    ubyte[6][32] fdbMac;
    ubyte[32] fdbPort;
    int      fdbN;
    uint     subnet, mask, gw;       // LAN addressing for domain interfaces (gateway VM = .1)
    int      nextHost;
}

private struct Route { bool used; uint dom; ubyte kind; int seg; uint viaDom; int domIf; }
enum : ubyte { RT_DIRECT = 0, RT_SEG = 1, RT_DOMAIN = 2 }

private struct NatEnt {
    bool   used;
    ubyte  proto;
    uint   inIp;   ushort inPort;    // the VM side
    uint   extIp;  ushort extPort;   // the remote side
    ubyte[6] inMac;
    ulong  lastMs;
}

private struct Lease { uint ip; ubyte[6] mac; bool used; }

private struct Pending { bool used; int port; uint hop; ushort len; ulong ms; ubyte[1514] frame; }

private __gshared VPort[VNET_MAX_PORTS] g_port;
private __gshared VSeg[VNET_MAX_SEGS]   g_seg;
private __gshared Route[VNET_MAX_ROUTES] g_route;
private __gshared NatEnt[VNET_NAT_SLOTS] g_nat;
private __gshared Lease[32] g_lease;
private __gshared Pending[16] g_pend;
private __gshared int   g_routerPort = -1;
private __gshared ulong g_nowMs;
private __gshared ulong g_natOut, g_natIn, g_natFull, g_dhcpAcks;
private __gshared uint  g_logN;

private void vlog(const(char)* s) { if (g_logN < 64) { ++g_logN; klog("[vnet] "); klog(s); } }

// ── small helpers ────────────────────────────────────────────────────────────────────────────
// Byte loops, not slice assignments: `a[x .. y] = b[..]` lowers to druntime's _d_array_slice_copy,
// which this kernel does not link.
private void cp(ubyte* d, const(ubyte)* s, size_t n) { foreach (i; 0 .. n) d[i] = s[i]; }
private void fillb(ubyte* d, ubyte v, size_t n) { foreach (i; 0 .. n) d[i] = v; }
private void setMac(ref ubyte[6] m, ubyte a, ubyte b, ubyte c, ubyte d, ubyte e, ubyte f) {
    m[0] = a; m[1] = b; m[2] = c; m[3] = d; m[4] = e; m[5] = f;
}
private ushort get16(const(ubyte)* p) { return cast(ushort)((p[0] << 8) | p[1]); }
private void   put16(ubyte* p, uint v) { p[0] = cast(ubyte)(v >> 8); p[1] = cast(ubyte)v; }
private uint   getIp(const(ubyte)* p) { uint v; cp(cast(ubyte*)&v, p, 4); return v; }
private void   putIp(ubyte* p, uint v) { cp(p, cast(const(ubyte)*)&v, 4); }
private uint   ipOf(ubyte a, ubyte b, ubyte c, ubyte d) { return IPv4Address(a, b, c, d).addr; }
private bool   macEq(const(ubyte)* a, const(ubyte)* b) { foreach (i; 0 .. 6) if (a[i] != b[i]) return false; return true; }
private bool   macBcast(const(ubyte)* m) { return (m[0] & 1) != 0; }   // broadcast or multicast
private bool   cstrEqN(const(char)* a, const(char)* b, size_t n) {
    foreach (i; 0 .. n) { if (a[i] != b[i]) return false; if (a[i] == 0) return true; }
    return true;
}
private size_t cstrLen(const(char)* s, size_t max) { size_t n = 0; while (n < max && s[n]) ++n; return n; }

/// Internet checksum over `len` bytes, starting from `sum` (big-endian words); returns the folded,
/// complemented value to store big-endian.
private ushort csumFold(uint sum) { while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16); return cast(ushort)~sum; }
private uint   csumAdd(uint sum, const(ubyte)* d, size_t len) {
    size_t i = 0;
    for (; i + 1 < len; i += 2) sum += (d[i] << 8) | d[i + 1];
    if (len & 1) sum += d[len - 1] << 8;
    return sum;
}
private ushort l4Csum(uint src, uint dst, ubyte proto, const(ubyte)* l4, size_t len) {
    ubyte[12] ph;
    putIp(ph.ptr, src); putIp(ph.ptr + 4, dst);
    ph[8] = 0; ph[9] = proto; put16(ph.ptr + 10, cast(uint)len);
    uint s = csumAdd(0, ph.ptr, 12);
    s = csumAdd(s, l4, len);
    return csumFold(s);
}
/// Recompute the checksum of a TCP/UDP/ICMP segment in place.
private void fixL4(uint src, uint dst, ubyte proto, ubyte* l4, size_t len) {
    if (proto == 6 && len >= 20)      { put16(l4 + 16, 0); put16(l4 + 16, l4Csum(src, dst, 6, l4, len)); }
    else if (proto == 17 && len >= 8) { put16(l4 + 6, 0);  ushort c = l4Csum(src, dst, 17, l4, len); put16(l4 + 6, c == 0 ? 0xFFFF : c); }
    else if (proto == 1 && len >= 4)  { put16(l4 + 2, 0);  put16(l4 + 2, csumFold(csumAdd(0, l4, len))); }
}
/// Build an IPv4 header at `p` (20 bytes).
private void ipHeader(ubyte* p, uint src, uint dst, ubyte proto, size_t l4len, ubyte ttl) {
    static __gshared ushort ident = 0x4000;
    p[0] = 0x45; p[1] = 0; put16(p + 2, cast(uint)(20 + l4len)); put16(p + 4, ++ident);
    put16(p + 6, 0); p[8] = ttl; p[9] = proto; put16(p + 10, 0);
    putIp(p + 12, src); putIp(p + 16, dst);
    put16(p + 10, csumFold(csumAdd(0, p, 20)));
}

// ── segments + ports ─────────────────────────────────────────────────────────────────────────
private int segFind(const(char)* name, bool create) {
    foreach (i; 0 .. VNET_MAX_SEGS)
        if (g_seg[i].used && cstrEqN(g_seg[i].name.ptr, name, g_seg[i].name.length)) return cast(int)i;
    if (!create) return -1;
    foreach (i; 0 .. VNET_MAX_SEGS) {
        if (g_seg[i].used) continue;
        g_seg[i] = VSeg.init;
        g_seg[i].used = true;
        const size_t n = cstrLen(name, g_seg[i].name.length - 1);
        cp(cast(ubyte*)&g_seg[i].name[0], cast(const(ubyte)*)&name[0], cast(size_t)((n) - (0)));
        g_seg[i].name[n] = 0;
        // LAN addressing a gateway VM's segment uses: OPNsense's factory LAN, 192.168.1.1/24.
        g_seg[i].subnet = ipOf(192, 168, 1, 0);
        g_seg[i].mask   = ipOf(255, 255, 255, 0);
        g_seg[i].gw     = ipOf(192, 168, 1, 1);
        g_seg[i].nextHost = 20;
        return cast(int)i;
    }
    return -1;
}

private int portAlloc(PortKind kind, int seg) {
    foreach (i; 1 .. VNET_MAX_PORTS) {
        if (g_port[i].used) continue;
        g_port[i] = VPort.init;
        g_port[i].used = true;
        g_port[i].kind = kind;
        g_port[i].seg  = seg;
        setMac(g_port[i].mac, 0x02, 0xa1, 0x00, cast(ubyte)seg, 0x00, cast(ubyte)i);
        return cast(int)i;
    }
    return -1;
}

private void fdbLearn(int seg, const(ubyte)* mac, int port) {
    auto s = &g_seg[seg];
    foreach (i; 0 .. s.fdbN) if (macEq(s.fdbMac[i].ptr, mac)) { s.fdbPort[i] = cast(ubyte)port; return; }
    const int slot = s.fdbN < 32 ? s.fdbN++ : cast(int)(g_nowMs % 32);
    cp(cast(ubyte*)&s.fdbMac[slot][0], cast(const(ubyte)*)&mac[0], cast(size_t)((6) - (0)));
    s.fdbPort[slot] = cast(ubyte)port;
}
private int fdbLookup(int seg, const(ubyte)* mac) {
    auto s = &g_seg[seg];
    foreach (i; 0 .. s.fdbN) if (macEq(s.fdbMac[i].ptr, mac)) return s.fdbPort[i];
    return -1;
}

private void portDeliver(int p, const(ubyte)* f, size_t len);

/// A frame entered segment `seg` from port `from`: learn its source, switch it.
private void segInput(int seg, int from, const(ubyte)* f, size_t len) {
    if (len < 14 || len > VNET_FRAME_MAX || seg < 0) return;
    if (!macBcast(f + 6)) fdbLearn(seg, f + 6, from);
    if (!macBcast(f)) {
        const int to = fdbLookup(seg, f);
        if (to > 0 && to != from && g_port[to].used && g_port[to].seg == seg) { portDeliver(to, f, len); return; }
    }
    foreach (i; 1 .. VNET_MAX_PORTS)                        // broadcast / unknown: flood
        if (i != from && g_port[i].used && g_port[i].seg == seg) portDeliver(cast(int)i, f, len);
}

private void emit(int port, const(ubyte)* dstMac, ushort etherType, const(ubyte)* payload, size_t len) {
    ubyte[VNET_FRAME_MAX] f;
    if (len + 14 > f.length) return;
    cp(cast(ubyte*)&f[0], cast(const(ubyte)*)&dstMac[0], cast(size_t)((6) - (0)));
    cp(cast(ubyte*)&f[6], cast(const(ubyte)*)&g_port[port].mac[0], cast(size_t)((12) - (6)));
    put16(f.ptr + 12, etherType);
    cp(cast(ubyte*)&f[14], cast(const(ubyte)*)&payload[0], cast(size_t)((14 + len) - (14)));
    ++g_port[port].tx;
    segInput(g_port[port].seg, port, f.ptr, 14 + len);
}

// ── TAP ports (/dev/net/tun) ─────────────────────────────────────────────────────────────────
/// Attach a TAP by interface name (TUNSETIFF).  Returns the port index or a negative errno.
public int vnetTapAttach(const(char)* name, uint flags) {
    import memory.mm : alloc_phys_pages;
    import core.exports : phys_to_virt;
    char[24] segName = 0;
    if ((name[0] == 'w' && name[1] == 'a' && name[2] == 'n') || (name[0] == 'n' && name[1] == 'a' && name[2] == 't')) {
        cp(cast(ubyte*)segName.ptr, cast(const(ubyte)*)"uplink".ptr, 6);
    } else {
        size_t n = 0;
        while (n < 23 && name[n] && name[n] != '.') { segName[n] = name[n]; ++n; }
        if (n == 0) return -22;
    }
    const int seg = segFind(segName.ptr, true);
    if (seg < 0) return -12;
    if (cstrEqN(segName.ptr, "uplink", 7)) vnetRouterEnsure(seg);
    foreach (i; 1 .. VNET_MAX_PORTS)                           // the same name again: a second open
        if (g_port[i].used && g_port[i].kind == PortKind.Tap && cstrEqN(g_port[i].name.ptr, name, 16)) {
            ++g_port[i].opens;
            return cast(int)i;
        }
    const int p = portAlloc(PortKind.Tap, seg);
    if (p < 0) return -12;
    const size_t pages = (VNET_QLEN * VFrame.sizeof + 4095) / 4096;
    const ulong phys = alloc_phys_pages(pages);
    if (phys == 0) { g_port[p].used = false; return -12; }
    g_port[p].qPhys = phys;
    g_port[p].q = cast(VFrame*)phys_to_virt(phys);
    const size_t n = cstrLen(name, 15);
    cp(cast(ubyte*)&g_port[p].name[0], cast(const(ubyte)*)&name[0], cast(size_t)((n) - (0)));
    g_port[p].tapFlags = flags;
    g_port[p].vnetHdr = 10;                // Linux's default until TUNSETVNETHDRSZ
    g_port[p].opens = 1;
    klog("[vnet] tap "); klog(g_port[p].name.ptr); klog(" -> segment "); klog(g_seg[seg].name.ptr);
    klog(" (port "); klog_dec(p); klog(")\n");
    return p;
}

public void vnetTapRelease(int p) {
    import memory.mm : free_phys_pages;
    if (p <= 0 || p >= VNET_MAX_PORTS || !g_port[p].used || g_port[p].kind != PortKind.Tap) return;
    if (--g_port[p].opens > 0) return;
    const size_t pages = (VNET_QLEN * VFrame.sizeof + 4095) / 4096;
    if (g_port[p].qPhys) free_phys_pages(g_port[p].qPhys, pages);
    klog("[vnet] tap "); klog(g_port[p].name.ptr); klog(" released\n");
    g_port[p].used = false;
}

public const(char)* vnetTapName(int p) { return (p > 0 && p < VNET_MAX_PORTS && g_port[p].used) ? g_port[p].name.ptr : null; }
public void vnetTapSetHdr(int p, uint sz) { if (p > 0 && p < VNET_MAX_PORTS && sz <= 12) g_port[p].vnetHdr = sz; }
public uint vnetTapHdr(int p) { return (p > 0 && p < VNET_MAX_PORTS) ? g_port[p].vnetHdr : 0; }
public uint vnetTapFlags(int p) { return (p > 0 && p < VNET_MAX_PORTS) ? g_port[p].tapFlags : 0; }
public bool vnetTapReadable(int p) { return p > 0 && p < VNET_MAX_PORTS && g_port[p].used && g_port[p].qLen > 0; }
public const(ubyte)* vnetTapMac(int p) { return (p > 0 && p < VNET_MAX_PORTS && g_port[p].used) ? g_port[p].mac.ptr : null; }

/// Find a TAP by name (SIOC* ioctls on sockets name interfaces, not fds).
public int vnetTapByName(const(char)* name) {
    foreach (i; 1 .. VNET_MAX_PORTS)
        if (g_port[i].used && g_port[i].kind == PortKind.Tap && cstrEqN(g_port[i].name.ptr, name, 16)) return cast(int)i;
    return -1;
}

/// The VMM read a frame: the virtio-net header (zeros: no offloads) followed by the frame.
public long vnetTapRead(int p, ubyte* dst, size_t cap) {
    if (p <= 0 || p >= VNET_MAX_PORTS || !g_port[p].used) return -9;
    auto port = &g_port[p];
    if (port.qLen == 0) return -11;                           // EAGAIN
    auto f = &port.q[port.qHead];
    const size_t h = port.vnetHdr;
    size_t n = h + f.len;
    if (n > cap) n = cap;                                    // truncate like a datagram
    foreach (i; 0 .. (h < n ? h : n)) dst[i] = 0;
    if (n > h) cp(cast(ubyte*)&dst[h], cast(const(ubyte)*)&f.data[0], cast(size_t)((n) - (h)));
    port.qHead = (port.qHead + 1) % VNET_QLEN;
    --port.qLen;
    return cast(long)n;
}

/// The VMM wrote a frame (header + frame): switch it onto the segment.
public long vnetTapWrite(int p, const(ubyte)* src, size_t len) {
    if (p <= 0 || p >= VNET_MAX_PORTS || !g_port[p].used) return -9;
    const size_t h = g_port[p].vnetHdr;
    if (len < h + 14) return cast(long)len;                  // runt: consumed, dropped
    ++g_port[p].rx;
    segInput(g_port[p].seg, p, src + h, len - h);
    return cast(long)len;
}

private void tapEnqueue(int p, const(ubyte)* f, size_t len) {
    auto port = &g_port[p];
    if (port.q is null || port.qLen >= VNET_QLEN) { ++port.drops; return; }
    auto slot = &port.q[(port.qHead + port.qLen) % VNET_QLEN];
    slot.len = cast(ushort)len;
    cp(cast(ubyte*)&slot.data[0], cast(const(ubyte)*)&f[0], cast(size_t)((len) - (0)));
    ++port.qLen;
    ++port.tx;
}

// ── the uplink router: ARP, ping, DHCP, NAT ──────────────────────────────────────────────────
private enum uint ROUTER_IP_B3 = 1;
private uint routerIp() { return ipOf(10, 77, 0, 1); }

private void vnetRouterEnsure(int seg) {
    if (g_routerPort > 0) return;
    const int p = portAlloc(PortKind.Router, seg);
    if (p < 0) return;
    setMac(g_port[p].mac, 0x02, 0xa0, 0x00, 0x00, 0x00, 0x01);
    g_port[p].ip = routerIp();
    g_port[p].mask = ipOf(255, 255, 255, 0);
    g_routerPort = p;
    g_seg[seg].subnet = ipOf(10, 77, 0, 0);
    g_seg[seg].gw = routerIp();
    vlog("uplink router 10.77.0.1/24 up (DHCP 10.77.0.2+, NAT via the host network)\n");
}

private void arpReply(int port, const(ubyte)* reqEth, const(ubyte)* arp) {
    ubyte[28] r;
    put16(r.ptr, 1); put16(r.ptr + 2, 0x0800); r[4] = 6; r[5] = 4; put16(r.ptr + 6, 2);
    cp(cast(ubyte*)&r[8], cast(const(ubyte)*)&g_port[port].mac[0], cast(size_t)((14) - (8)));
    putIp(r.ptr + 14, g_port[port].ip);
    cp(cast(ubyte*)&r[18], cast(const(ubyte)*)&arp[8], cast(size_t)((24) - (18)));
    cp(cast(ubyte*)&r[24], cast(const(ubyte)*)&arp[14], cast(size_t)((28) - (24)));
    emit(port, arp + 8, 0x0806, r.ptr, 28);
}
private void arpRequest(int port, uint target) {
    ubyte[28] r;
    put16(r.ptr, 1); put16(r.ptr + 2, 0x0800); r[4] = 6; r[5] = 4; put16(r.ptr + 6, 1);
    cp(cast(ubyte*)&r[8], cast(const(ubyte)*)&g_port[port].mac[0], cast(size_t)((14) - (8)));
    putIp(r.ptr + 14, g_port[port].ip);
    fillb(r.ptr + 18, 0, 6);
    putIp(r.ptr + 24, target);
    static immutable ubyte[6] bc = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    emit(port, bc.ptr, 0x0806, r.ptr, 28);
}

private uint leaseFor(const(ubyte)* mac) {
    foreach (i; 0 .. g_lease.length) if (g_lease[i].used && macEq(g_lease[i].mac.ptr, mac)) return g_lease[i].ip;
    foreach (i; 0 .. g_lease.length) {
        if (g_lease[i].used) continue;
        g_lease[i].used = true;
        cp(cast(ubyte*)&g_lease[i].mac[0], cast(const(ubyte)*)&mac[0], cast(size_t)((6) - (0)));
        g_lease[i].ip = ipOf(10, 77, 0, cast(ubyte)(2 + i));
        return g_lease[i].ip;
    }
    return 0;
}

private void dhcpServe(int port, const(ubyte)* eth, const(ubyte)* ip, const(ubyte)* udp, size_t ulen) {
    const(ubyte)* b = udp + 8;
    const size_t blen = ulen - 8;
    if (blen < 240 || b[0] != 1 || b[236] != 99 || b[237] != 130 || b[238] != 83 || b[239] != 99) return;
    int type = 0;
    for (size_t o = 240; o + 1 < blen && b[o] != 255; ) {
        if (b[o] == 0) { ++o; continue; }
        if (b[o] == 53 && o + 2 < blen) type = b[o + 2];
        o += 2 + b[o + 1];
    }
    if (type != 1 && type != 3) return;                       // DISCOVER / REQUEST
    const uint yi = leaseFor(b + 28);
    if (yi == 0) return;
    ubyte[300] r = 0;
    r[0] = 2; r[1] = 1; r[2] = 6;
    cp(cast(ubyte*)&r[4], cast(const(ubyte)*)&b[4], cast(size_t)((8) - (4)));                                     // xid
    cp(cast(ubyte*)&r[10], cast(const(ubyte)*)&b[10], cast(size_t)((12) - (10)));                                 // flags
    putIp(r.ptr + 16, yi);
    putIp(r.ptr + 20, routerIp());
    cp(cast(ubyte*)&r[28], cast(const(ubyte)*)&b[28], cast(size_t)((44) - (28)));                                 // chaddr
    r[236] = 99; r[237] = 130; r[238] = 83; r[239] = 99;
    size_t o = 240;
    r[o++] = 53; r[o++] = 1; r[o++] = cast(ubyte)(type == 1 ? 2 : 5);
    r[o++] = 54; r[o++] = 4; putIp(r.ptr + o, routerIp()); o += 4;
    r[o++] = 51; r[o++] = 4; r[o++] = 0; r[o++] = 1; r[o++] = 0x51; r[o++] = 0x80;   // 86400 s
    r[o++] = 1;  r[o++] = 4; putIp(r.ptr + o, ipOf(255, 255, 255, 0)); o += 4;
    r[o++] = 3;  r[o++] = 4; putIp(r.ptr + o, routerIp()); o += 4;
    {
        import network.dns : getDNSServer;
        IPv4Address dns; getDNSServer(&dns);
        r[o++] = 6; r[o++] = 4; putIp(r.ptr + o, dns.addr != 0 ? dns.addr : ipOf(9, 9, 9, 9)); o += 4;
    }
    r[o++] = 255;
    const size_t blen2 = o < 300 ? 300 : o;
    ubyte[8 + 300] u = 0;
    put16(u.ptr, 67); put16(u.ptr + 2, 68); put16(u.ptr + 4, cast(uint)(8 + blen2));
    cp(cast(ubyte*)&u[8], cast(const(ubyte)*)&r[0], cast(size_t)((8 + blen2) - (8)));
    const uint bcast = 0xFFFFFFFF;
    fixL4(routerIp(), bcast, 17, u.ptr, 8 + blen2);
    ubyte[20 + 8 + 300] pkt;
    ipHeader(pkt.ptr, routerIp(), bcast, 17, 8 + blen2, 64);
    cp(cast(ubyte*)&pkt[20], cast(const(ubyte)*)&u[0], cast(size_t)((28 + blen2) - (20)));
    static immutable ubyte[6] bc = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    emit(port, bc.ptr, 0x0800, pkt.ptr, 28 + blen2);
    if (type == 3) {
        ++g_dhcpAcks;
        klog("[vnet] DHCP: leased "); klog_dec(IPv4Address(yi).bytes[3]); klog(" of 10.77.0.0/24 to a VM on the uplink\n");
    }
}

private int natAlloc(ubyte proto, uint inIp, ushort inPort, uint extIp, ushort extPort, const(ubyte)* inMac) {
    int victim = -1; ulong oldest = ulong.max;
    foreach (i; 0 .. VNET_NAT_SLOTS) {
        auto e = &g_nat[i];
        if (e.used && e.proto == proto && e.inIp == inIp && e.inPort == inPort && e.extIp == extIp && e.extPort == extPort) {
            e.lastMs = g_nowMs; return cast(int)i;
        }
    }
    foreach (i; 0 .. VNET_NAT_SLOTS) {
        auto e = &g_nat[i];
        const ulong ttl = e.proto == 6 ? 600_000 : e.proto == 17 ? 120_000 : 30_000;
        if (!e.used || g_nowMs - e.lastMs > ttl) { victim = cast(int)i; break; }
        if (e.lastMs < oldest) { oldest = e.lastMs; victim = cast(int)i; }
    }
    if (victim < 0) { ++g_natFull; return -1; }
    auto e = &g_nat[victim];
    e.used = true; e.proto = proto; e.inIp = inIp; e.inPort = inPort; e.extIp = extIp; e.extPort = extPort;
    cp(cast(ubyte*)&e.inMac[0], cast(const(ubyte)*)&inMac[0], cast(size_t)((6) - (0))); e.lastMs = g_nowMs;
    return victim;
}

/// A VM on the uplink sent an IPv4 packet that is not for the router: NAT it out.
private void natOut(const(ubyte)* eth, const(ubyte)* ip, size_t iplen) {
    const size_t ihl = (ip[0] & 15) * 4;
    const size_t tot = get16(ip + 2);
    if (ihl < 20 || tot > iplen || tot <= ihl) return;
    if ((get16(ip + 6) & 0x3FFF) != 0) return;                // fragments: not handled
    const ubyte proto = ip[9];
    const uint src = getIp(ip + 12), dst = getIp(ip + 16);
    const size_t l4len = tot - ihl;
    ubyte[1500] l4;
    cp(cast(ubyte*)&l4[0], cast(const(ubyte)*)&ip[ihl], cast(size_t)((l4len) - (0)));
    int slot = -1;
    if ((proto == 6 || proto == 17) && l4len >= 8) {
        slot = natAlloc(proto, src, get16(l4.ptr), dst, get16(l4.ptr + 2), eth + 6);
        if (slot < 0) return;
        put16(l4.ptr, VNET_NAT_BASE + slot);
    } else if (proto == 1 && l4len >= 8 && l4[0] == 8) {       // echo request: map the identifier
        slot = natAlloc(1, src, get16(l4.ptr + 4), dst, 0, eth + 6);
        if (slot < 0) return;
        put16(l4.ptr + 4, VNET_NAT_BASE + slot);
    } else return;
    import network.ipv4 : ipv4Send, ipv4HostIP;
    const uint me = ipv4HostIP();
    if (me == 0) return;
    fixL4(me, dst, proto, l4.ptr, l4len);
    const int prev = g_netIf;
    g_netIf = 0;
    const IPv4Address d = IPv4Address(dst);
    if (ipv4Send(d, proto, l4.ptr, l4len)) ++g_natOut;
    g_netIf = prev;
}

/// Called by the host stack for every packet addressed to the host (before local delivery):
/// true when it was a NAT reply, now switched back to the VM.
public bool vnetNatInbound(ubyte proto, const(ubyte)* l4, size_t len, const ref IPv4Address srcIP) {
    if (g_routerPort <= 0 || len < 8) return false;
    int slot = -1;
    if (proto == 6 || proto == 17) {
        const uint dp = get16(l4 + 2);
        if (dp < VNET_NAT_BASE || dp >= VNET_NAT_BASE + VNET_NAT_SLOTS) return false;
        slot = cast(int)(dp - VNET_NAT_BASE);
        auto e = &g_nat[slot];
        if (!e.used || e.proto != proto || e.extIp != srcIP.addr || e.extPort != get16(l4)) return false;
    } else if (proto == 1 && l4[0] == 0) {
        const uint id = get16(l4 + 4);
        if (id < VNET_NAT_BASE || id >= VNET_NAT_BASE + VNET_NAT_SLOTS) return false;
        slot = cast(int)(id - VNET_NAT_BASE);
        auto e = &g_nat[slot];
        if (!e.used || e.proto != 1 || e.extIp != srcIP.addr) return false;
    } else return false;
    auto e = &g_nat[slot];
    e.lastMs = g_nowMs;
    if (len > 1480) return true;
    ubyte[1500] pkt;
    ubyte* out4 = pkt.ptr + 20;
    cp(cast(ubyte*)&out4[0], cast(const(ubyte)*)&l4[0], cast(size_t)((len) - (0)));
    if (proto == 1) put16(out4 + 4, e.inPort); else put16(out4 + 2, e.inPort);
    fixL4(srcIP.addr, e.inIp, proto, out4, len);
    ipHeader(pkt.ptr, srcIP.addr, e.inIp, proto, len, 63);
    ++g_natIn;
    emit(g_routerPort, e.inMac.ptr, 0x0800, pkt.ptr, 20 + len);
    return true;
}

private void routerInput(const(ubyte)* f, size_t len) {
    const int rp = g_routerPort;
    const ushort et = get16(f + 12);
    const(ubyte)* pl = f + 14;
    const size_t plen = len - 14;
    if (et == 0x0806 && plen >= 28) {
        if (get16(pl + 6) == 1 && getIp(pl + 24) == g_port[rp].ip) arpReply(rp, f, pl);
        return;
    }
    if (et != 0x0800 || plen < 20) return;
    const uint dst = getIp(pl + 16);
    const size_t ihl = (pl[0] & 15) * 4;
    const ubyte proto = pl[9];
    if (dst == g_port[rp].ip || dst == 0xFFFFFFFF) {
        if (proto == 17 && plen >= ihl + 8 && get16(pl + ihl + 2) == 67) {
            dhcpServe(rp, f, pl, pl + ihl, get16(pl + 2) - ihl);
        } else if (proto == 1 && dst == g_port[rp].ip && plen >= ihl + 8 && pl[ihl] == 8) {
            const size_t l4len = get16(pl + 2) - ihl;
            ubyte[1500] pkt;
            cp(cast(ubyte*)&pkt[20], cast(const(ubyte)*)&pl[ihl], cast(size_t)((20 + l4len) - (20)));
            pkt[20] = 0;                                               // echo reply
            fixL4(g_port[rp].ip, getIp(pl + 12), 1, pkt.ptr + 20, l4len);
            ipHeader(pkt.ptr, g_port[rp].ip, getIp(pl + 12), 1, l4len, 64);
            emit(rp, f + 6, 0x0800, pkt.ptr, 20 + l4len);
        }
        return;
    }
    if ((dst & 0xFF) == 10 && IPv4Address(dst).bytes[1] == 77) return;   // stays on the uplink
    natOut(f, pl, plen);
}

// ── domain interfaces ────────────────────────────────────────────────────────────────────────
private bool domArpLookup(int p, uint ip, ubyte* mac) {
    auto port = &g_port[p];
    foreach (i; 0 .. port.arpN) if (port.arpIp[i] == ip) { cp(cast(ubyte*)&mac[0], cast(const(ubyte)*)&port.arpMac[i][0], cast(size_t)((6) - (0))); return true; }
    return false;
}
private void domArpLearn(int p, uint ip, const(ubyte)* mac) {
    auto port = &g_port[p];
    foreach (i; 0 .. port.arpN) if (port.arpIp[i] == ip) { cp(cast(ubyte*)&port.arpMac[i][0], cast(const(ubyte)*)&mac[0], cast(size_t)((6) - (0))); return; }
    const int slot = port.arpN < 8 ? port.arpN++ : cast(int)(g_nowMs % 8);
    port.arpIp[slot] = ip; cp(cast(ubyte*)&port.arpMac[slot][0], cast(const(ubyte)*)&mac[0], cast(size_t)((6) - (0)));
}

private void pendFlush(int p, uint ip, const(ubyte)* mac) {
    foreach (i; 0 .. g_pend.length) {
        auto q = &g_pend[i];
        if (!q.used || q.port != p || q.hop != ip) continue;
        cp(cast(ubyte*)&q.frame[0], cast(const(ubyte)*)&mac[0], cast(size_t)((6) - (0)));
        ++g_port[p].tx;
        segInput(g_port[p].seg, p, q.frame.ptr, q.len);
        q.used = false;
    }
}

/// ipv4Send() for a domain interface.
public bool vnetIfSendIPv4(int p, const ref IPv4Address dst, ubyte proto, const(ubyte)* payload, size_t len) {
    if (p <= 0 || p >= VNET_MAX_PORTS || !g_port[p].used || g_port[p].kind != PortKind.DomIf) return false;
    if (len + 34 > 1514) return false;
    auto port = &g_port[p];
    ubyte[1514] f;
    ipHeader(f.ptr + 14, port.ip, dst.addr, proto, len, 64);
    cp(cast(ubyte*)&f[34], cast(const(ubyte)*)&payload[0], cast(size_t)((34 + len) - (34)));
    cp(cast(ubyte*)&f[6], cast(const(ubyte)*)&port.mac[0], cast(size_t)((12) - (6)));
    put16(f.ptr + 12, 0x0800);
    if (dst.isBroadcast()) {
        fillb(f.ptr, 0xff, 6);
        ++port.tx;
        segInput(port.seg, p, f.ptr, 34 + len);
        return true;
    }
    const uint hop = ((dst.addr & port.mask) == (port.ip & port.mask)) ? dst.addr : port.gw;
    ubyte[6] mac;
    if (domArpLookup(p, hop, mac.ptr)) {
        cp(cast(ubyte*)&f[0], cast(const(ubyte)*)&mac[0], cast(size_t)((6) - (0)));
        ++port.tx;
        segInput(port.seg, p, f.ptr, 34 + len);
        return true;
    }
    foreach (i; 0 .. g_pend.length) {                          // queue it behind an ARP request
        auto q = &g_pend[i];
        if (q.used && g_nowMs - q.ms < 3000) continue;
        q.used = true; q.port = p; q.hop = hop; q.len = cast(ushort)(34 + len); q.ms = g_nowMs;
        cp(cast(ubyte*)&q.frame[0], cast(const(ubyte)*)&f[0], cast(size_t)((34 + len) - (0)));
        break;
    }
    arpRequest(p, hop);
    return true;                                               // in flight (TCP retransmits if it is lost)
}

private void domIfInput(int p, const(ubyte)* f, size_t len) {
    import network.icmp : icmpHandlePacket;
    import network.udp : udpHandlePacket;
    import network.tcp : tcpHandlePacket;
    auto port = &g_port[p];
    const ushort et = get16(f + 12);
    const(ubyte)* pl = f + 14;
    const size_t plen = len - 14;
    if (et == 0x0806 && plen >= 28) {
        const uint sip = getIp(pl + 14);
        domArpLearn(p, sip, pl + 8);
        pendFlush(p, sip, pl + 8);
        if (get16(pl + 6) == 1 && getIp(pl + 24) == port.ip) arpReply(p, f, pl);
        return;
    }
    if (et != 0x0800 || plen < 20) return;
    const size_t ihl = (pl[0] & 15) * 4;
    const size_t tot = get16(pl + 2);
    if (ihl < 20 || tot > plen || tot < ihl) return;
    if (csumFold(csumAdd(0, pl, ihl)) != 0) return;
    const uint dst = getIp(pl + 16);
    if (dst != port.ip && dst != 0xFFFFFFFF) return;
    domArpLearn(p, getIp(pl + 12), f + 6);
    ++port.rx;
    const IPv4Address src = IPv4Address(getIp(pl + 12));
    const int prev = g_netIf;
    g_netIf = p;
    switch (pl[9]) {
        case 1:  icmpHandlePacket(pl + ihl, tot - ihl, src); break;
        case 17: udpHandlePacket(pl + ihl, tot - ihl, src); break;
        case 6:  tcpHandlePacket(pl + ihl, tot - ihl, src); break;
        default: break;
    }
    g_netIf = prev;
}

public bool vnetIfAddr(int p, IPv4Address* ip) {
    if (p <= 0 || p >= VNET_MAX_PORTS || !g_port[p].used || g_port[p].kind != PortKind.DomIf) return false;
    ip.addr = g_port[p].ip;
    return true;
}

private void portDeliver(int p, const(ubyte)* f, size_t len) {
    final switch (g_port[p].kind) {
        case PortKind.Tap:    tapEnqueue(p, f, len); break;
        case PortKind.Router: routerInput(f, len); break;
        case PortKind.DomIf:  domIfInput(p, f, len); break;
        case PortKind.None:   break;
    }
}

/// The domain interface of domain `dom` on segment `seg`, created on first use.
private int domIfFor(uint dom, int seg) {
    foreach (i; 1 .. VNET_MAX_PORTS)
        if (g_port[i].used && g_port[i].kind == PortKind.DomIf && g_port[i].domain == dom && g_port[i].seg == seg)
            return cast(int)i;
    const int p = portAlloc(PortKind.DomIf, seg);
    if (p < 0) return -1;
    auto s = &g_seg[seg];
    auto port = &g_port[p];
    port.domain = dom;
    port.mask = s.mask;
    port.gw = s.gw;
    IPv4Address a = IPv4Address(s.subnet);
    a.bytes[3] = cast(ubyte)(s.nextHost < 250 ? s.nextHost++ : 250);
    port.ip = a.addr;
    const size_t n = cstrLen(s.name.ptr, 11);
    cp(cast(ubyte*)port.name.ptr, cast(const(ubyte)*)"dom-".ptr, 4);
    foreach (i; 0 .. n) port.name[4 + i] = s.name[i];
    klog("[vnet] domain 0x"); klog_hex(dom); klog(" joins "); klog(s.name.ptr); klog(" as 192.168.1.");
    klog_dec(a.bytes[3]); klog(" (gateway .1)\n");
    return p;
}

// ── routes ───────────────────────────────────────────────────────────────────────────────────
private Route* routeOf(uint dom, bool create) {
    foreach (i; 0 .. VNET_MAX_ROUTES) if (g_route[i].used && g_route[i].dom == dom) return &g_route[i];
    if (!create) return null;
    foreach (i; 0 .. VNET_MAX_ROUTES) if (!g_route[i].used) { g_route[i] = Route.init; g_route[i].used = true; g_route[i].dom = dom; return &g_route[i]; }
    return null;
}

/// `route <domain> direct | vm:<segment> | domain:<name>` (the Domain Manager's verb).
public bool vnetSetRoute(uint dom, const(char)* arg) {
    import core.domain : domainByName;
    if (dom == 0 || arg is null) return false;
    if (cstrEqN(arg, "direct", 7)) {
        auto r = routeOf(dom, false);
        if (r !is null) r.used = false;
        klog("[vnet] route: domain 0x"); klog_hex(dom); klog(" -> direct\n");
        return true;
    }
    if (arg[0] == 'v' && arg[1] == 'm' && arg[2] == ':') {
        const int seg = segFind(arg + 3, true);             // a segment may be named before its VM runs
        if (seg < 0) return false;
        auto r = routeOf(dom, true);
        if (r is null) return false;
        r.kind = RT_SEG; r.seg = seg; r.viaDom = 0;
        klog("[vnet] route: domain 0x"); klog_hex(dom); klog(" -> through the VM on "); klog(g_seg[seg].name.ptr); klog("\n");
        return true;
    }
    if (cstrEqN(arg, "domain:", 7)) {
        const uint via = domainByName(arg + 7);
        if (via == 0 || via == dom) return false;
        auto r = routeOf(dom, true);
        if (r is null) return false;
        r.kind = RT_DOMAIN; r.viaDom = via; r.seg = -1;
        klog("[vnet] route: domain 0x"); klog_hex(dom); klog(" -> through domain "); klog(arg + 7); klog("\n");
        return true;
    }
    return false;
}

/// Resolve a domain's route: 0 = the host network, > 0 = the domain interface to use, -1 = no way
/// out (a loop, or too deep): fail closed.
public int vnetIfForDomain(uint dom) {
    uint cur = dom;
    foreach (hop; 0 .. 8) {
        auto r = routeOf(cur, false);
        if (r is null) return 0;
        if (r.kind == RT_SEG) return domIfFor(dom, r.seg);
        if (r.kind == RT_DOMAIN) { cur = r.viaDom; if (cur == dom) return -1; continue; }
        return 0;
    }
    return -1;
}

public void vnetTick(ulong nowMs) { g_nowMs = nowMs; }

// ── status: /config/vnet.json ────────────────────────────────────────────────────────────────
private struct JBuf { char* p; size_t cap, n; }
private void js(ref JBuf b, const(char)* s) { while (*s && b.n + 1 < b.cap) b.p[b.n++] = *s++; }
private void jd(ref JBuf b, ulong v) {
    char[24] t; int k = 0;
    do { t[k++] = cast(char)('0' + v % 10); v /= 10; } while (v && k < 24);
    while (k) { if (b.n + 1 < b.cap) b.p[b.n++] = t[--k]; else --k; }
}
private void jip(ref JBuf b, uint ip) {
    const IPv4Address a = IPv4Address(ip);
    js(b, "\""); jd(b, a.bytes[0]); js(b, "."); jd(b, a.bytes[1]); js(b, "."); jd(b, a.bytes[2]); js(b, ".");
    jd(b, a.bytes[3]); js(b, "\"");
}

/// Render the virtual network as JSON (segments with their ports, routes, NAT counters).
public size_t vnetRenderJson(char* buf, size_t cap) {
    import core.domain : domainNameOf;
    JBuf b = JBuf(buf, cap, 0);
    js(b, "{\"segments\":[");
    bool first = true;
    foreach (s; 0 .. VNET_MAX_SEGS) {
        if (!g_seg[s].used) continue;
        if (!first) js(b, ",");
        first = false;
        js(b, "{\"name\":\""); js(b, g_seg[s].name.ptr); js(b, "\",\"gateway\":"); jip(b, g_seg[s].gw);
        js(b, ",\"ports\":[");
        bool pf = true;
        foreach (p; 1 .. VNET_MAX_PORTS) {
            if (!g_port[p].used || g_port[p].seg != cast(int)s) continue;
            if (!pf) js(b, ",");
            pf = false;
            js(b, "{\"kind\":\"");
            js(b, g_port[p].kind == PortKind.Tap ? "vm" : g_port[p].kind == PortKind.Router ? "router" : "domain");
            js(b, "\",\"name\":\""); js(b, g_port[p].name.ptr); js(b, "\"");
            if (g_port[p].kind != PortKind.Tap) { js(b, ",\"ip\":"); jip(b, g_port[p].ip); }
            if (g_port[p].kind == PortKind.DomIf) {
                const(char)* dn = domainNameOf(g_port[p].domain);
                js(b, ",\"domain\":\""); js(b, dn !is null ? dn : "?"); js(b, "\"");
            }
            js(b, ",\"rx\":"); jd(b, g_port[p].rx); js(b, ",\"tx\":"); jd(b, g_port[p].tx);
            js(b, ",\"drops\":"); jd(b, g_port[p].drops); js(b, "}");
        }
        js(b, "]}");
    }
    js(b, "],\"routes\":[");
    first = true;
    foreach (i; 0 .. VNET_MAX_ROUTES) {
        if (!g_route[i].used) continue;
        if (!first) js(b, ",");
        first = false;
        const(char)* dn = domainNameOf(g_route[i].dom);
        js(b, "{\"domain\":\""); js(b, dn !is null ? dn : "?"); js(b, "\",\"via\":\"");
        if (g_route[i].kind == RT_SEG) { js(b, "vm:"); js(b, g_seg[g_route[i].seg].name.ptr); }
        else { const(char)* vn = domainNameOf(g_route[i].viaDom); js(b, "domain:"); js(b, vn !is null ? vn : "?"); }
        js(b, "\"}");
    }
    js(b, "],\"nat\":{\"out\":"); jd(b, g_natOut); js(b, ",\"in\":"); jd(b, g_natIn);
    js(b, ",\"full\":"); jd(b, g_natFull); js(b, ",\"dhcpAcks\":"); jd(b, g_dhcpAcks); js(b, "}}\n");
    if (b.n < cap) buf[b.n] = 0;
    return b.n;
}
