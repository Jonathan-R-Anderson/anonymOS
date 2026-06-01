module core.bundle;

import core.globals;
import core.utils;
import core.io;

extern(C) @nogc nothrow:

struct BundleFile {
    const(char)* name;
    ulong nameLen;
    ulong offset;
    ulong size;
}

__gshared void* g_bundleBase = null;
__gshared ulong g_bundleSize = 0;
__gshared ulong g_fileCount = 0;

// Since we can't easily allocate dynamic arrays yet in this context without full runtime,
// we'll traverse the bundle linearly on lookup or pointer arithmetic.
// The header is:
// Magic (8 bytes)
// Count (8 bytes)
// [NameLen(8), Name(len), Offset(8), Size(8)]...

public void initBundle(void* base, ulong size) {
    if (base == null) return;
    
    ubyte* b = cast(ubyte*)base;
    
    // Check Magic: HOSBNDL1
    if (b[0] != 'H' || b[1] != 'O' || b[2] != 'S' || b[3] != 'B' ||
        b[4] != 'N' || b[5] != 'D' || b[6] != 'L' || b[7] != '1') {
        klog("Bundle magic mismatch!\n");
        return;
    }
    
    g_bundleBase = base;
    g_bundleSize = size;
    g_fileCount = *cast(ulong*)(b + 8);
    
    klog("Bundle initialized. Files: ");
    klog_hex(g_fileCount);
    klog("\n");
}

public bool findBundleFile(const(char)* name, out BundleFile result) {
    if (g_bundleBase == null) return false;
    
    ubyte* ptr = cast(ubyte*)g_bundleBase + 16; // Skip Magic + Count
    
    for(ulong i=0; i<g_fileCount; i++) {
        ulong nameLen = *cast(ulong*)ptr; 
        ptr += 8;
        
        const(char)* fileName = cast(const(char)*)ptr;
        
        // Check match
        if (streq(name, fileName, nameLen)) {
            result.name = fileName;
            result.nameLen = nameLen;
            ptr += nameLen;
            result.offset = *cast(ulong*)ptr;
            ptr += 8;
            result.size = *cast(ulong*)ptr;
            return true;
        }
        
        ptr += nameLen;
        ptr += 8; // Offset
        ptr += 8; // Size
    }
    
    return false;
}

public long bundleRead(ulong fileOffset, ulong fileSize, ulong readOffset, void* buf, ulong count) {
    if (readOffset >= fileSize) return 0;
    
    ulong remaining = fileSize - readOffset;
    ulong toRead = count;
    if (toRead > remaining) toRead = remaining;
    
    ubyte* src = cast(ubyte*)g_bundleBase + fileOffset + readOffset;
    ubyte* dst = cast(ubyte*)buf;
    
    for(ulong i=0; i<toRead; i++) {
        dst[i] = src[i];
    }
    
    return cast(long)toRead;
}

private bool streq(const(char)* s1, const(char)* s2, ulong len2) {
    ulong i = 0;
    while(s1[i] != 0 && i < len2) {
        if (s1[i] != s2[i]) return false;
        i++;
    }
    return s1[i] == 0 && i == len2;
}

public align(1) struct CBundleFileResult {
    ulong offset;
    ulong size;
}

extern(C) bool c_findBundleFile(const(char)* name, ulong nameLen, CBundleFileResult* outRes) {
    BundleFile bf;
    // We need a null-terminated string for findBundleFile if we use the current implementation? 
    // Actually findBundleFile takes const(char)* name but does streq which checks for 0 termination on s1 (the name passed in).
    // So we should ensure the name passed from Haskell is null-terminated or we modify streq.
    // simpler: allow matching with length.
    
    // Let's modify findBundleFile to take length or just use the one we have.
    // Actually, `streq` implementation:
    // while(s1[i] != 0 && i < len2)
    
    // If we pass a pointer from Haskell, it might not be null terminated if it's a CString it is.
    // HSA: readCString gives [Char]. withCString gives null-terminated.
    
    if (findBundleFile(name, bf)) { // findBundleFile expects null-terminated name
        outRes.offset = bf.offset;
        outRes.size = bf.size;
        return true;
    }
    return false;
}
