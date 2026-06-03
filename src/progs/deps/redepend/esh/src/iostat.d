module iostat;

import std.stdio;
import std.string;
import std.conv;
import std.algorithm;
import shell.syscalls;

string readProc(string path) {
    int fd = cast(int)sys_open(path.toStringz, 0);
    if(fd < 0) return "";
    ubyte[4096] buf;
    long n;
    string content;
    while((n = sys_read(fd, buf.ptr, 4096)) > 0)
        content ~= cast(string)buf[0..n];
    sys_close(fd);
    return content;
}

void iostatCommand(string[] tokens) {
    writeln("avg-cpu:  %user   %nice %system %iowait  %steal   %idle");
    
    string stat = readProc("/proc/stat");
    if(stat.length) {
        foreach(line; stat.splitLines) {
            if(line.startsWith("cpu ")) {
                auto parts = line.split();
                if(parts.length >= 8) {
                    // user nice system idle iowait irq softirq steal
                    long user = to!long(parts[1]);
                    long nice = to!long(parts[2]);
                    long sys = to!long(parts[3]);
                    long idle = to!long(parts[4]);
                    long iowait = to!long(parts[5]);
                    long irq = to!long(parts[6]);
                    long soft = to!long(parts[7]);
                    long steal = 0; // sometimes 8th or 9th depending on kernel
                    
                    long total = user + nice + sys + idle + iowait + irq + soft + steal;
                    if(total == 0) total = 1;
                    
                    writefln("          %6.2f  %6.2f  %6.2f  %6.2f  %6.2f  %6.2f",
                        (cast(double)user/total)*100.0,
                        (cast(double)nice/total)*100.0,
                        (cast(double)sys/total)*100.0,
                        (cast(double)iowait/total)*100.0,
                        (cast(double)steal/total)*100.0,
                        (cast(double)idle/total)*100.0
                    );
                }
            }
        }
    } else {
        writeln("          0.00   0.00   0.00   0.00   0.00  100.00");
    }
    
    writeln("\nDevice             tps    kB_read/s    kB_wrtn/s    kB_read    kB_wrtn");
    // Parse /proc/diskstats or /proc/partitions?
    // /proc/diskstats: major minor name ... reads merges sectors ...
    // Simplified listing
    
    string diskstats = readProc("/proc/diskstats");
    if(diskstats.length) {
        foreach(line; diskstats.splitLines) {
            auto parts = line.split();
            // 8 0 sda 100 0 200 ...
            if(parts.length >= 14) {
                 string name = parts[2];
                 if(name.startsWith("loop") || name.startsWith("ram")) continue; 
                 // sectors read = parts[5]. sectors written = parts[9].
                 // 512b sectors usually.
                 long secRead = to!long(parts[5]);
                 long secWrite = to!long(parts[9]);
                 double kbRead = (secRead * 512) / 1024.0;
                 double kbWrite = (secWrite * 512) / 1024.0;
                 
                 writefln("%-16s %6.2f %12.2f %12.2f %10.0f %10.0f",
                     name, 0.0, 0.0, 0.0, kbRead, kbWrite);
            }
        }
    }
}
