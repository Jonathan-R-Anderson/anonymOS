module df;

import std.stdio;
import std.conv;

string humanSize(ulong bytes, bool showBytes = true) {
    if (showBytes || bytes < 1024) return to!string(bytes) ~ "B";
    if (bytes < 1024 * 1024) return to!string(bytes / 1024) ~ "K";
    if (bytes < 1024 * 1024 * 1024) return to!string(bytes / (1024 * 1024)) ~ "M";
    return to!string(bytes / (1024 * 1024 * 1024)) ~ "G";
}

void dfCommand(string[] tokens) {
    writeln("Filesystem      Size  Used Avail Use% Mounted on");
    writeln("/dev/root       1.0G  512M  512M  50% /");
    writeln("tmpfs           256M    0  256M   0% /tmp");
}
