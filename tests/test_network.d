import kernel.hardware.network;

void main()
{
    NetPacket p;
    p.len = 0;
    net_init();
    net_send(&p);
    auto n = net_receive(&p);
    assert(n == 0);
}
