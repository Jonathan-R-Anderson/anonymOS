// HOST STUB for core.io — used only by tests/virt/host.
//
// klog -> stdout via printf; klog_hex -> %lx.  The PASS/FAIL lines the
// harness greps for come through here.
module core.io;

import core.stdc.stdio : printf;

extern (C) @nogc nothrow:

public void klog(const(char)* msg) {
    if (msg is null) return;
    printf("%s", msg);
}

public void klog_hex(ulong val) {
    printf("%lx", val);
}

public void klog_dec(ulong val) {
    printf("%lu", val);
}
