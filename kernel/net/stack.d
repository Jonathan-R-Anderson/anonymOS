module kernel.net.stack;

pragma(LDC_no_moduleinfo);

import kernel.net.arp       : arp_init, arp_process;
import kernel.net.ip        : ip_init;
import kernel.net.ethernet  : EthernetHeader, ETH_TYPE_ARP;
import kernel.hardware.network : net_receive, NetPacket;
import kernel.logger : log_message;

public:

extern(C) void net_stack_init(const(ubyte)* mac, uint ip)
{
    arp_init(mac, ip);
    ip_init(ip);
    log_message("network stack initialized\n");
}

// Poll for incoming packets and dispatch to protocols
extern(C) void net_poll()
{
    NetPacket pkt;
    auto len = net_receive(&pkt);
    if(len == 0) return;

    if(len < EthernetHeader.sizeof) return;
    auto eth = cast(const(EthernetHeader)*)(pkt.data.ptr);
    ushort ethType = (eth.eth_type >> 8) | ((eth.eth_type & 0xFF) << 8);

    const(ubyte)* payload = pkt.data.ptr + EthernetHeader.sizeof;
    auto pl_len = len - EthernetHeader.sizeof;

    if(ethType == ETH_TYPE_ARP)
    {
        arp_process(payload, pl_len);
    }
}
