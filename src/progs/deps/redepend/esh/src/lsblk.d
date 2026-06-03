module lsblk;

import std.stdio;
import std.file; // dirEntries, readText
import std.path;
import std.string;

import std.algorithm;
import std.conv;

string humanSize(long bytes) {
    if (bytes < 1024) return to!string(bytes) ~ "B";
    double kb = bytes / 1024.0;
    if (kb < 1024) return format("%.1fK", kb);
    double mb = kb / 1024.0;
    if (mb < 1024) return format("%.1fM", mb);
    double gb = mb / 1024.0;
    return format("%.1fG", gb);
}

void lsblkCommand(string[] tokens) {
    bool showBytes = false;
    foreach(t; tokens) if(t=="-b"||t=="--bytes") showBytes = true;

    writeln("NAME          MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT");
    
    if(!exists("/sys/block")) return;
    
    foreach(entry; dirEntries("/sys/block", SpanMode.shallow)) {
        string dev = entry.name.baseName;
        if(dev.startsWith("loop") || dev.startsWith("ram")) continue;
        
        string sizeStr = "0";
        try { sizeStr = readText("/sys/block/" ~ dev ~ "/size").strip; } catch(Exception){}
        long blocks = 0;
        try { blocks = to!long(sizeStr); } catch(Exception){}
        long size = blocks * 512;
        
        string sStr = showBytes ? to!string(size) : humanSize(size);
        
        string rem = "0";
        try { rem = readText("/sys/block/" ~ dev ~ "/removable").strip; } catch(Exception){}
        
        string ro = "0";
        try { ro = readText("/sys/block/" ~ dev ~ "/ro").strip; } catch(Exception){}
        
        writefln("%-12s  %3d:%-3d  %s %5s  %s disk", 
            dev, 8, 0, rem, sStr, ro); // simplistic major/minor
            
        // partitions? /sys/block/sda/sda1
        foreach(p; dirEntries("/sys/block/" ~ dev, SpanMode.shallow)) {
             string pName = p.name.baseName;
             if(pName.startsWith(dev)) {
                 // partition
                 string pSizeS = "0";
                 try { pSizeS = readText(p.name ~ "/size").strip; } catch(Exception){}
                 long pBlocks = 0; try { pBlocks = to!long(pSizeS); } catch(Exception){}
                 long pSize = pBlocks * 512;
                 string pSStr = showBytes ? to!string(pSize) : humanSize(pSize);
                 
                 writefln("└─%-10s  %3d:%-3d  %s %5s  %s part", 
                    pName, 8, 1, "0", pSStr, "0");
             }
        }
    }
}
