module kernel.net.ethernet;

pragma(LDC_no_moduleinfo);

import kernel.hardware.network : NetPacket, net_send;
import kernel.logger : log_message;

public:

struct EthernetHeader
{
    ubyte[6] dst;
    ubyte[6] src;
    ushort eth_type; // Big endian
}

enum ETH_TYPE_ARP = 0x0806;
enum ETH_TYPE_IP  = 0x0800;

// Send raw Ethernet frame using the hardware driver
extern(C) void eth_send(const(ubyte)* data, size_t len)
{
    NetPacket pkt;
    if(len > pkt.data.length)
        len = pkt.data.length;
    foreach(i; 0 .. len)
        pkt.data[i] = data[i];
    pkt.len = len;
    net_send(&pkt);
}
