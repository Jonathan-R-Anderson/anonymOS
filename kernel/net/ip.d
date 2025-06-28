module kernel.net.ip;

pragma(LDC_no_moduleinfo);

import kernel.net.ethernet : EthernetHeader, ETH_TYPE_IP, eth_send;
import kernel.net.common   : swap16, swap32;
import kernel.net.checksum : checksum16;
import kernel.net.arp      : arp_lookup, arp_send_request, localMac;
import kernel.logger       : log_message;

public:

struct IpHeader
{
    ubyte  ver_ihl;      // Version (4) + IHL (4)
    ubyte  tos;
    ushort tot_len;
    ushort id;
    ushort frag_off;
    ubyte  ttl;
    ubyte  proto;
    ushort checksum;
    uint   src;
    uint   dst;
}

enum IP_PROTO_UDP = 17;

__gshared uint localIp;

extern(C) void ip_init(uint ip)
{
    localIp = ip;
}

// Build and send IPv4 packet
extern(C) void ip_send(uint dstIp, ubyte proto, const(ubyte)* payload, size_t len)
{
    ubyte[sizeof(EthernetHeader) + sizeof(IpHeader) + 1500] buf; // allocate enough
    auto eth = cast(EthernetHeader*)buf.ptr;

    const(ubyte)* dstMac = arp_lookup(dstIp);
    if(dstMac is null)
    {
        arp_send_request(dstIp);
        log_message("dst MAC unknown, sent ARP request\n");
        return;
    }
    eth.dst[] = dstMac[0 .. 6];
    eth.src[] = localMac;
    eth.eth_type = swap16(ETH_TYPE_IP);

    auto ip = cast(IpHeader*)(buf.ptr + EthernetHeader.sizeof);
    ip.ver_ihl = 0x45; // IPv4, 5*4=20 byte header
    ip.tos = 0;
    ip.tot_len = swap16(cast(ushort)(IpHeader.sizeof + len));
    ip.id = swap16(1);
    ip.frag_off = 0;
    ip.ttl = 64;
    ip.proto = proto;
    ip.src = swap32(localIp);
    ip.dst = swap32(dstIp);
    ip.checksum = 0;
    ip.checksum = checksum16(cast(const ubyte*)ip, IpHeader.sizeof);

    // Copy payload
    ubyte* p = buf.ptr + EthernetHeader.sizeof + IpHeader.sizeof;
    foreach(i; 0 .. len)
        p[i] = payload[i];

    auto total = EthernetHeader.sizeof + IpHeader.sizeof + len;
    eth_send(buf.ptr, total);
}
