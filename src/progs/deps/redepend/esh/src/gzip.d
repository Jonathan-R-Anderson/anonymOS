module gzip;

import std.stdio;
import std.digest.crc;
import std.string : toStringz;
import shell.syscalls;
import std.algorithm : startsWith;

void gzipFile(string filename) {
    auto fdIn = sys_open(filename.toStringz, 0);
    if (fdIn < 0) {
        writeln("gzip: ", filename, ": No such file");
        return;
    }
    
    string outFile = filename ~ ".gz";
    auto fdOut = sys_open(outFile.toStringz, 0x241, 420); // create
    if (fdOut < 0) {
        writeln("gzip: cannot create ", outFile);
        sys_close(cast(int)fdIn);
        return;
    }
    
    // GZIP Header
    ubyte[10] header = [0x1f, 0x8b, 0x08, 0x00, 0,0,0,0, 0x00, 0x03];
    sys_write(cast(int)fdOut, header.ptr, 10);
    
    CRC32 crc;
    crc.start();
    uint totalSize = 0;
    
    ubyte[32768] buf; // 32k buffer
    long n;
    while ((n = sys_read(cast(int)fdIn, buf.ptr, 32768)) > 0) {
        ushort len = cast(ushort)n;
        ushort nlen = cast(ushort)(~len);
        
        ubyte[5] blockHeader;
        blockHeader[0] = 0x00; // BFINAL=0, BTYPE=00
        blockHeader[1] = cast(ubyte)(len & 0xFF);
        blockHeader[2] = cast(ubyte)(len >> 8);
        blockHeader[3] = cast(ubyte)(nlen & 0xFF);
        blockHeader[4] = cast(ubyte)(nlen >> 8);
        
        sys_write(cast(int)fdOut, blockHeader.ptr, 5);
        sys_write(cast(int)fdOut, buf.ptr, n);
        
        crc.put(buf[0..n]);
        totalSize += cast(uint)n;
    }
    
    // Write Empty Final Block
    ubyte[5] finalBlock = [0x01, 0x00, 0x00, 0xFF, 0xFF];
    sys_write(cast(int)fdOut, finalBlock.ptr, 5);
    
    sys_close(cast(int)fdIn);
    
    auto crcVal = crc.finish();
    ubyte[4] crcLE;
    crcLE[0] = crcVal[3];
    crcLE[1] = crcVal[2];
    crcLE[2] = crcVal[1];
    crcLE[3] = crcVal[0];
    sys_write(cast(int)fdOut, crcLE.ptr, 4);
    
    ubyte[4] sizeLE;
    sizeLE[0] = cast(ubyte)(totalSize & 0xFF);
    sizeLE[1] = cast(ubyte)((totalSize >> 8) & 0xFF);
    sizeLE[2] = cast(ubyte)((totalSize >> 16) & 0xFF);
    sizeLE[3] = cast(ubyte)((totalSize >> 24) & 0xFF);
    sys_write(cast(int)fdOut, sizeLE.ptr, 4);
    
    sys_close(cast(int)fdOut);
    
    sys_unlink(filename.toStringz);
}

void gzipCommand(string[] tokens) {
    if (tokens.length < 2) {
        writeln("gzip: missing operand");
        return;
    }
    foreach(file; tokens[1..$]) {
        if (file.startsWith("-")) continue; // skip flags
        gzipFile(file);
    }
}
