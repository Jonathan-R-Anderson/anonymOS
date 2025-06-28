module kernel.net.arp;

pragma(LDC_no_moduleinfo);

import kernel.net.ethernet : EthernetHeader, ETH_TYPE_ARP, eth_send;
import kernel.net.common   : swap16, swap32;
import kernel.logger       : log_message;

public:

struct ArpHeader
{
    ushort htype; // hardware type
    ushort ptype; // protocol type
    ubyte  hlen;
    ubyte  plen;
    ushort oper; // operation
    ubyte[6] sha; // sender hardware address
    uint sip;     // sender IP
    ubyte[6] tha; // target hardware address
    uint tip;     // target IP
}

enum ARP_HTYPE_ETHERNET = 1;
enum ARP_PTYPE_IPV4 = 0x0800;
enum ARP_OPER_REQUEST = 1;
enum ARP_OPER_REPLY   = 2;

struct ArpEntry
{
    uint ip;
    ubyte[6] mac;
}

enum MAX_ARP = 16;
__gshared ArpEntry[MAX_ARP] arpTable;
__gshared size_t arpCount;
__gshared ubyte[6] localMac;
__gshared uint localIp;

extern(C) void arp_init(const(ubyte)* mac, uint ip)
{
    arpCount = 0;
    foreach(i; 0 .. 6)
        localMac[i] = mac[i];
    localIp = ip;
}

// Lookup MAC from IP
extern(C) const(ubyte)* arp_lookup(uint ip)
{
    foreach(i; 0 .. arpCount)
        if(arpTable[i].ip == ip)
            return arpTable[i].mac.ptr;
    return null;
}

// Send ARP request for target IP
extern(C) void arp_send_request(uint targetIp)
{
    ArpHeader hdr;
    hdr.htype = swap16(ARP_HTYPE_ETHERNET);
    hdr.ptype = swap16(ARP_PTYPE_IPV4);
    hdr.hlen = 6;
    hdr.plen = 4;
    hdr.oper = swap16(ARP_OPER_REQUEST);
    hdr.sha = localMac;
    hdr.sip = swap32(localIp);
    hdr.tha = [0,0,0,0,0,0];
    hdr.tip = swap32(targetIp);

    ubyte[sizeof(EthernetHeader)+sizeof(ArpHeader)] frame;
    auto eth = cast(EthernetHeader*)frame.ptr;
    eth.dst[] = [0xFF,0xFF,0xFF,0xFF,0xFF,0xFF];
    eth.src[] = localMac;
    eth.eth_type = swap16(ETH_TYPE_ARP);

    auto p = cast(ArpHeader*)(frame.ptr + EthernetHeader.sizeof);
    *p = hdr;

    eth_send(frame.ptr, frame.length);
    log_message("ARP request sent\n");
}

// Process incoming ARP packet
extern(C) void arp_process(const(ubyte)* data, size_t len)
{
    if(len < ArpHeader.sizeof) return;
    auto hdr = cast(const(ArpHeader)*)(data);
    ushort oper = swap16(hdr.oper);
    uint sip = swap32(hdr.sip);
    if(oper == ARP_OPER_REPLY)
    {
        if(arpCount < MAX_ARP)
        {
            arpTable[arpCount].ip = sip;
            foreach(i; 0 .. 6)
                arpTable[arpCount].mac[i] = hdr.sha[i];
            ++arpCount;
            log_message("ARP reply stored\n");
        }
    }
}
