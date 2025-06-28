import std.stdio;
import std.socket;
import std.datetime.stopwatch : StopWatch;
import std.getopt;

void traceroute(string host, int maxHops) {
    auto dest = InternetAddress(host, 33434);
    foreach (ttl; 1 .. maxHops+1) {
        auto sock = new UdpSocket(AddressFamily.INET);
        sock.setOption(SocketOptionLevel.IP, SocketOption.IP_TTL, ttl);
        sock.timeout = dur!msecs(1000);
        StopWatch sw; sw.start();
        sock.sendTo("\0", dest);
        ubyte[512] buf;
        auto from = new InternetAddress();
        bool received = false;
        try {
            auto len = sock.receiveFrom(buf, from);
            received = true;
        } catch (SocketTimeoutException) {
        }
        sw.stop();
        if (received)
            writeln(ttl, " ", from.toString(), " ", sw.peek.msecs, " ms");
        else
            writeln(ttl, " *");
        if (received && from.address == dest.address)
            break;
    }
}

void main(string[] args) {
    int cycles = 10;
    auto res = getopt(args, "c", &cycles);
    if (res.helpWanted || res.rest.length == 0) {
        writeln("Usage: mtr [-c cycles] HOST");
        return;
    }
    traceroute(res.rest[0], cycles);
}
