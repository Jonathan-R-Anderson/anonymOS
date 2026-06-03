module md5sum;

import std.stdio;
import std.digest.md;
import std.string : toStringz;
import shell.syscalls;

// Library function for objectsystem.d
string hexDigest(const(ubyte)[] data) {
    auto md5 = MD5();
    md5.put(data);
    auto result = md5.finish();
    return toHexString(result); 
}

// Library function for interpreter.d
string md5sumStdin() {
    MD5 md5;
    md5.start();
    ubyte[4096] buf;
    long n;
    while ((n = sys_read(0, buf.ptr, 4096)) > 0) {
        md5.put(buf[0..n]);
    }
    return toHexString(md5.finish());
}

void md5sumFile(string filename) {
    auto fd = sys_open(filename.toStringz, 0);
    if (fd < 0) {
        writeln("md5sum: ", filename, ": No such file or directory");
        return;
    }
    
    MD5 md5;
    md5.start();
    
    ubyte[4096] buf;
    long n;
    while ((n = sys_read(cast(int)fd, buf.ptr, 4096)) > 0) {
        md5.put(buf[0..n]);
    }
    sys_close(cast(int)fd);
    
    auto result = md5.finish();
    write(toHexString(result)); 
    writeln("  ", filename);
}

// Manual hex string 
string toHexString(ubyte[16] data) {
    import std.format;
    import std.array;
    auto app = appender!string();
    foreach(b; data) app.put(format("%02x", b));
    return app.data;
}

void md5sumCommand(string[] tokens) {
    if (tokens.length < 2) {
        writeln(md5sumStdin(), "  -");
        return;
    }
    
    foreach(file; tokens[1..$]) {
        md5sumFile(file);
    }
}
