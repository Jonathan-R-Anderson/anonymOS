module core.kmain;

import arch.x86_64.limine;
import arch.x86_64.bootstrap;
import arch.x86_64.arch;
import core.globals;
import core.io;
import ldc.attributes;
import ldc.llvmasm;

extern (C):

// Start Marker
@(section(".limine_reqs"))
align(8) __gshared ulong[4] limine_requests_start = [0xf6b8f4b39de7d1ae, 0xfab91a6940fcb9cf, 0x785c6ed015d3e316, 0x181e920a7852b9d9];

// Base Revision
@(section(".limine_reqs"))
align(8) __gshared limine_base_revision base_revision = { 
    id0: 0xf9562b2d5c95a6c8, 
    id1: 0x6a7b384944536bdc, 
    revision: 1
};

// Requests
@(section(".limine_reqs"))
align(8) __gshared limine_memmap_request memmap_req = { id0: LIMINE_COMMON_MAGIC_0, id1: LIMINE_COMMON_MAGIC_1, id2: 0x67cf3d9d378a806f, id3: 0xe304acdfc50c3c62, revision: 0, response: null };

@(section(".limine_reqs"))
align(8) __gshared limine_module_request module_req = { id0: LIMINE_COMMON_MAGIC_0, id1: LIMINE_COMMON_MAGIC_1, id2: 0x3e7e279702be32af, id3: 0xca1c4f3bd1280cee, revision: 0, response: null, internal_module_count: 0, internal_modules: null };

@(section(".limine_reqs"))
align(8) __gshared limine_kernel_address_request kernel_addr_req = { id0: LIMINE_COMMON_MAGIC_0, id1: LIMINE_COMMON_MAGIC_1, id2: 0x71ba76863cc55f63, id3: 0xb2644a48c516a487, revision: 0, response: null };

@(section(".limine_reqs"))
align(8) __gshared limine_hhdm_request hhdm_req = { id0: LIMINE_COMMON_MAGIC_0, id1: LIMINE_COMMON_MAGIC_1, id2: 0x48dcf1cb8ad2b852, id3: 0x63984e959a98244b, revision: 0, response: null };

@(section(".limine_reqs"))
align(8) __gshared limine_paging_mode_request paging_req = { 
    id0: LIMINE_COMMON_MAGIC_0, id1: LIMINE_COMMON_MAGIC_1, id2: 0x95c1a0edab0944cb, id3: 0xa4e5cb3842f7488a,
    revision: 0, 
    response: null,
    mode: LIMINE_PAGING_MODE_X86_64_4LVL,
    flags: 0
};

@(section(".limine_reqs"))
align(8) __gshared limine_stack_size_request stack_req = {
    id0: LIMINE_COMMON_MAGIC_0, id1: LIMINE_COMMON_MAGIC_1, id2: 0x224ef0460a8e8926, id3: 0xe1cb0fc25f46ea3d,
    revision: 0,
    response: null,
    stack_size: 0x100000 // 1MB
};

@(section(".limine_reqs"))
align(8) __gshared limine_framebuffer_request framebuffer_req = {
    id0: LIMINE_COMMON_MAGIC_0, id1: LIMINE_COMMON_MAGIC_1, id2: 0x9d5827dcd881dd75, id3: 0xa3148604f6fab11b,
    revision: 0,
    response: null
};

@(section(".limine_reqs"))
align(8) __gshared limine_terminal_request terminal_req = {
    id0: LIMINE_COMMON_MAGIC_0, id1: LIMINE_COMMON_MAGIC_1, id2: 0xc8ac59310c2b0844, id3: 0xa68d0c7265d38878,
    revision: 0,
    response: null,
    callback: null
};

// End Marker
@(section(".limine_reqs"))
align(8) __gshared ulong[2] limine_requests_end = [0xadc0e0531bb10d03, 0x9572709f31764c62];

extern __gshared ulong hhdm_offset;


void initializeKernelCore() {
    // D owns early platform bring-up (CPU, boot protocol and memory handoff).
    enable_sse();
    klog("AnonymOS Kernel Starting...\n");
    klog("Base Revision Addr: "); klog_hex(cast(ulong)&base_revision); klog("\n");
    klog("Base Rev Magic 0:  "); klog_hex(base_revision.id0); klog("\n");
    klog("Base Rev Magic 1:  "); klog_hex(base_revision.id1); klog("\n");
    klog("Base Revision Val: "); klog_hex(base_revision.revision); klog("\n");

    if (paging_req.response) {
        klog("Paging Mode: "); klog_hex(paging_req.response.mode); klog("\n");
        klog("Paging Flags: "); klog_hex(paging_req.response.flags); klog("\n");
    }

    if (hhdm_req.response) {
        hhdm_offset = hhdm_req.response.offset;
        klog("HHDM Offset: "); klog_hex(hhdm_offset); klog("\n");
    }
}

void _start() {
    initializeKernelCore();

    // Hand off from D core to runtime/bootstrap bridge used by Haskell kernel logic.
    bootstrap_kernel(memmap_req.response, kernel_addr_req.response, module_req.response, terminal_req.response, framebuffer_req.response);

    hcf();
}

void hcf() {
    __asm("cli", "");
    while(1) {
        __asm("hlt", "");
    }
}
