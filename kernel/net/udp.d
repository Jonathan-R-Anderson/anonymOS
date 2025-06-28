module kernel.net.udp;

pragma(LDC_no_moduleinfo);

import kernel.net.ip       : ip_send, IP_PROTO_UDP, localIp;
import kernel.net.common   : swap16, swap32;
import kernel.net.checksum : checksum16;
import kernel.logger       : log_message;

public:

struct UdpHeader
{
    ushort src_port;
    ushort dst_port;
    ushort len;
    ushort checksum;
}

// Send UDP datagram
extern(C) void udp_send(uint dstIp, ushort srcPort, ushort dstPort, const(ubyte)* data, size_t len)
{
    ubyte[sizeof(UdpHeader) + 1500] buf;
    auto udp = cast(UdpHeader*)buf.ptr;
    udp.src_port = swap16(srcPort);
    udp.dst_port = swap16(dstPort);
    udp.len = swap16(cast(ushort)(UdpHeader.sizeof + len));
    udp.checksum = 0;

    ubyte* payload = buf.ptr + UdpHeader.sizeof;
    foreach(i; 0 .. len)
        payload[i] = data[i];

    // Pseudo header for checksum
    ubyte[12 + sizeof(UdpHeader) + 1500] pseudo; // over-alloc
    auto p = pseudo.ptr;
    *(cast(uint*)p) = swap32(localIp); p += 4;
    *(cast(uint*)p) = swap32(dstIp);  p += 4;
    *p++ = 0;
    *p++ = IP_PROTO_UDP;
    *(cast(ushort*)p) = udp.len; p += 2;
    // Copy UDP header + data
    foreach(i; 0 .. UdpHeader.sizeof + len)
        p[i] = buf[i];

    udp.checksum = checksum16(pseudo.ptr, 12 + UdpHeader.sizeof + len);

    ip_send(dstIp, IP_PROTO_UDP, buf.ptr, UdpHeader.sizeof + len);
}
