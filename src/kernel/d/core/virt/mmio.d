// MMIO instruction decoder — turns the guest instruction that faulted on an
// MMIO access (EPT violation / SLAT fault) into a normalized access descriptor
// {read/write, size, data register or immediate, instruction length}.
//
// Why this exists: a hardware EPT violation reports the faulting guest-physical
// ADDRESS and the access type (read/write), but NOT the operand size, the data
// value (for writes), or the destination register (for reads).  KVM fills those
// in for userspace (and for in-kernel ioeventfd matching) by decoding the
// faulting instruction.  This module is that decoder.
//
// Scope: the instruction forms compilers actually emit for MMIO — plain MOV to
// and from memory (0x88/0x89/0x8A/0x8B), MOV immediate-to-memory (0xC6/0xC7),
// and MOVZX/MOVSX (0F B6/B7/BE/BF).  Register-direct forms (ModRM.mod==3) are
// rejected (not a memory access).  Addressing is 32-/64-bit (protected/long
// mode); 16-bit real-mode addressing is out of scope (guests do MMIO in
// protected/long mode).  Unsupported forms return {valid:false} so the caller
// falls back to a full userspace MMIO exit rather than guessing.
//
// Pure + testable: mmioDecode() takes a byte buffer and a mode flag and returns
// the descriptor — no guest-memory or VMCS access.  mmioDecodeSelfTest() drives
// it with synthetic encodings at boot.
//
// Constraints: -betterC, @nogc nothrow.
module core.virt.mmio;

import core.io : klog;
import core.virt.vm : Vm, Vcpu;
import core.virt.slat : slatLookup;
import core.virt.kvmabi : KvmRegs, KvmSRegs, KvmRun, KVM_EXIT_MMIO;
import core.exports : phys_to_virt;

extern (C) @nogc nothrow:

struct MmioAccess {
    bool  valid;      // decode succeeded (a supported MMIO memory-access form)
    bool  isWrite;    // true = store to memory (MMIO), false = load from memory
    ubyte size;       // access size in bytes: 1, 2, 4 or 8
    ubyte insnLen;    // total instruction length in bytes (to advance guest RIP)
    ubyte reg;        // x86 GPR number (0..15, REX-extended) holding the data
                      //   (write source / read destination); unused when isImm
    bool  isImm;      // true = store of an immediate (reg unused)
    long  imm;        // sign-extended immediate value (when isImm)
    bool  zeroExtend; // load form is MOVZX (informational for the caller)
    bool  signExtend; // load form is MOVSX
}

// Decode the MMIO memory-access instruction at `p` (up to `n` valid bytes).
// `is64` selects 64-bit mode (REX prefixes honored, RIP-relative addressing).
// Returns {valid:false} for anything not a supported simple MMIO access.
public MmioAccess mmioDecode(const(ubyte)* p, size_t n, bool is64) {
    MmioAccess a;   // zero-initialized: valid=false
    if (p is null || n == 0) return a;

    size_t i = 0;
    bool opsize16 = false;   // 0x66 operand-size override
    // ---- legacy prefixes (order-insensitive); track only operand size ----
    for (; i < n; ++i) {
        const ubyte b = p[i];
        if (b == 0x66) { opsize16 = true; continue; }        // operand-size
        if (b == 0x67) continue;                              // address-size (no length impact for 32/64-bit disp)
        if (b == 0xF0 || b == 0xF2 || b == 0xF3) continue;    // LOCK / REPNE / REP
        if (b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65)
            continue;                                          // segment overrides
        break;
    }
    // ---- REX (64-bit only), immediately precedes the opcode ----
    ubyte rex = 0;
    if (is64 && i < n && (p[i] & 0xF0) == 0x40) { rex = p[i]; ++i; }
    const bool rexW = (rex & 0x08) != 0;
    const bool rexR = (rex & 0x04) != 0;
    if (i >= n) return a;

    // operand size: REX.W -> 8, else 0x66 -> 2, else 4
    const ubyte osize = rexW ? 8 : (opsize16 ? 2 : 4);

    ubyte op = p[i]; ++i;
    bool isWrite = false;
    ubyte accSize = osize;
    bool hasImm = false; ubyte immSize = 0; bool regIsData = true;
    bool needRegZero = false; // opcode-extension forms require ModRM.reg == 0

    if (op == 0x0F) {
        if (i >= n) return a;
        const ubyte op2 = p[i]; ++i;
        switch (op2) {
            case 0xB6: isWrite = false; accSize = 1; a.zeroExtend = true; break; // MOVZX r, r/m8
            case 0xB7: isWrite = false; accSize = 2; a.zeroExtend = true; break; // MOVZX r, r/m16
            case 0xBE: isWrite = false; accSize = 1; a.signExtend = true; break; // MOVSX r, r/m8
            case 0xBF: isWrite = false; accSize = 2; a.signExtend = true; break; // MOVSX r, r/m16
            default: return a;
        }
    } else {
        switch (op) {
            case 0x88: isWrite = true;  accSize = 1;     break;                       // MOV r/m8, r8
            case 0x89: isWrite = true;  accSize = osize; break;                       // MOV r/m, r
            case 0x8A: isWrite = false; accSize = 1;     break;                       // MOV r8, r/m
            case 0x8B: isWrite = false; accSize = osize; break;                       // MOV r, r/m
            case 0xC6: isWrite = true;  accSize = 1;     hasImm = true; immSize = 1;
                       regIsData = false; needRegZero = true; break;                  // MOV r/m8, imm8
            case 0xC7: isWrite = true;  accSize = osize; hasImm = true;
                       immSize = (osize == 2 ? 2 : 4);                                 // imm16 or imm32 (sign-ext to 64)
                       regIsData = false; needRegZero = true; break;                  // MOV r/m, imm
            default: return a;
        }
    }

    // ---- ModRM ----
    if (i >= n) return a;
    const ubyte modrm = p[i]; ++i;
    const ubyte mod = (modrm >> 6) & 3;
    const ubyte reg = (modrm >> 3) & 7;
    const ubyte rm  = modrm & 7;
    if (mod == 3) return a;                    // register-direct operand: not MMIO
    if (needRegZero && reg != 0) return a;      // C6/C7: /0 only is MOV
    const ubyte regNum = cast(ubyte)(reg | (rexR ? 8 : 0));

    // ---- SIB ----
    ubyte sibBase = 0; bool hasSib = (rm == 4);
    if (hasSib) {
        if (i >= n) return a;
        sibBase = cast(ubyte)(p[i] & 7); ++i;
    }
    // ---- displacement ----
    ubyte dispSize = 0;
    if (mod == 1) dispSize = 1;
    else if (mod == 2) dispSize = 4;
    else { // mod == 0
        if (!hasSib && rm == 5) dispSize = 4;            // [disp32] (32-bit) / RIP-relative (64-bit)
        else if (hasSib && sibBase == 5) dispSize = 4;   // SIB with no base register
    }
    i += dispSize;
    if (i > n) return a;

    // ---- immediate ----
    long immVal = 0;
    if (hasImm) {
        if (i + immSize > n) return a;
        ulong u = 0;
        foreach (k; 0 .. immSize) u |= (cast(ulong)p[i + k]) << (8 * k);
        if (immSize == 1)      immVal = cast(long) cast(byte)  cast(ubyte)  u;
        else if (immSize == 2) immVal = cast(long) cast(short) cast(ushort) u;
        else                   immVal = cast(long) cast(int)   cast(uint)   u;
        i += immSize;
    }
    if (i > n || i > 15) return a;              // x86 instructions are at most 15 bytes

    a.valid   = true;
    a.isWrite = isWrite;
    a.size    = accSize;
    a.insnLen = cast(ubyte) i;
    a.isImm   = hasImm;
    a.imm     = immVal;
    a.reg     = regIsData ? regNum : 0;
    return a;
}

// x86 GPR number (ModRM/REX encoding) -> KvmRegs field index.  KvmRegs order is
// rax,rbx,rcx,rdx,rsi,rdi,rsp,rbp,r8..r15; the ModRM/REX number order is
// rax,rcx,rdx,rbx,rsp,rbp,rsi,rdi,r8..r15 — they differ for indices 1..7.
private ulong mmioRegValue(const(KvmRegs)* regs, ubyte x86reg) {
    ubyte idx;
    switch (x86reg) {
        case 0:  idx = 0; break; // rax
        case 1:  idx = 2; break; // rcx
        case 2:  idx = 3; break; // rdx
        case 3:  idx = 1; break; // rbx
        case 4:  idx = 6; break; // rsp
        case 5:  idx = 7; break; // rbp
        case 6:  idx = 4; break; // rsi
        case 7:  idx = 5; break; // rdi
        case 8: .. case 15: idx = x86reg; break; // r8..r15 line up
        default: return 0;
    }
    return (&regs.rax)[idx];
}

// Read `len` bytes at guest-physical `gpa` through EPT (per-page), into dst.
private bool readGuestPhys(Vm* vm, ulong gpa, ubyte* dst, size_t len) @nogc nothrow {
    size_t done = 0;
    while (done < len) {
        const ulong hpa = slatLookup(&vm.slat, (gpa + done) & ~0xFFFUL);
        if (hpa == 0) return false;
        auto page = cast(ubyte*)phys_to_virt(hpa);
        ulong off = (gpa + done) & 0xFFF;
        while (off < 4096 && done < len) { dst[done++] = page[off]; ++off; }
    }
    return true;
}
private bool readGuestPte64(Vm* vm, ulong gpa, out ulong v) @nogc nothrow {
    ubyte[8] b = 0;
    if (!readGuestPhys(vm, gpa, b.ptr, 8)) return false;
    v = 0; foreach (k; 0 .. 8) v |= (cast(ulong)b[k]) << (8 * k);
    return true;
}
private bool readGuestPte32(Vm* vm, ulong gpa, out uint v) @nogc nothrow {
    ubyte[4] b = 0;
    if (!readGuestPhys(vm, gpa, b.ptr, 4)) return false;
    v = 0; foreach (k; 0 .. 4) v |= (cast(uint)b[k]) << (8 * k);
    return true;
}

private enum ulong PTE_P    = 1UL << 0;                 // present
private enum ulong PTE_PS   = 1UL << 7;                 // page size (large page)
private enum ulong PADDR_52 = 0x000F_FFFF_FFFF_F000UL;  // 4KB frame, bits 51:12

// Translate a guest LINEAR address to guest-PHYSICAL via the guest page tables
// (rooted at cr3), reading each table through EPT.  Handles long-mode 4-level
// (incl. 1G/2M large pages) and legacy 32-bit 2-level non-PAE (incl. 4M).
// Returns false if any level is not-present or a table read fails.
public bool guestTranslate(Vm* vm, ulong cr3, ulong lin, bool longmode, out ulong gpa) @nogc nothrow {
    if (vm is null) return false;
    if (longmode) {
        ulong e; ulong base = cr3 & PADDR_52;
        if (!readGuestPte64(vm, base + ((lin >> 39) & 0x1FF) * 8, e) || !(e & PTE_P)) return false;
        base = e & PADDR_52;                                               // PML4E -> PDPT
        if (!readGuestPte64(vm, base + ((lin >> 30) & 0x1FF) * 8, e) || !(e & PTE_P)) return false;
        if (e & PTE_PS) { gpa = (e & 0x000F_FFFF_C000_0000UL) | (lin & 0x3FFF_FFFF); return true; } // 1G
        base = e & PADDR_52;                                               // PDPTE -> PD
        if (!readGuestPte64(vm, base + ((lin >> 21) & 0x1FF) * 8, e) || !(e & PTE_P)) return false;
        if (e & PTE_PS) { gpa = (e & 0x000F_FFFF_FFE0_0000UL) | (lin & 0x001F_FFFF); return true; }  // 2M
        base = e & PADDR_52;                                               // PDE -> PT
        if (!readGuestPte64(vm, base + ((lin >> 12) & 0x1FF) * 8, e) || !(e & PTE_P)) return false;
        gpa = (e & PADDR_52) | (lin & 0xFFF);
        return true;
    }
    // legacy 32-bit 2-level (non-PAE)
    uint e; ulong base = cr3 & 0xFFFF_F000UL;
    if (!readGuestPte32(vm, base + ((lin >> 22) & 0x3FF) * 4, e) || !(e & 1)) return false;
    if (e & 0x80) { gpa = (cast(ulong)(e & 0xFFC0_0000)) | (lin & 0x003F_FFFF); return true; }        // 4M
    base = cast(ulong)(e & 0xFFFF_F000);
    if (!readGuestPte32(vm, base + ((lin >> 12) & 0x3FF) * 4, e) || !(e & 1)) return false;
    gpa = (cast(ulong)(e & 0xFFFF_F000)) | (lin & 0xFFF);
    return true;
}

// Enrich a SLAT-fault MMIO exit (KVM_EXIT_MMIO, len still 0) by decoding the
// faulting guest instruction to fill mmio.len and, for writes, mmio.data.
// Returns true if it decoded and filled the exit; false if it declined (caller
// leaves len=0 and userspace decodes).  Scope: UNPAGED-FLAT guests (RIP linear
// == guest-physical, CS base 0); paged guests need a guest CR3 page-table walk
// and fall back to false for now.  For reads, mmio.len is set so userspace/the
// device knows the width; the read-completion writeback into the destination
// register happens on KVM_RUN re-entry (a later tier).
public bool mmioEnrichMmioExit(Vm* vm, Vcpu* vc, const(KvmRegs)* regs,
                               const(KvmSRegs)* sregs, KvmRun* run) @nogc nothrow {
    if (vm is null || regs is null || run is null) return false;
    if (run.exitReason != KVM_EXIT_MMIO) return false;
    if (run.u.mmio.len != 0) return true;                 // already decoded
    const bool paged    = sregs !is null && (sregs.cr0 & (1UL << 31)) != 0; // CR0.PG
    const bool pae      = sregs !is null && (sregs.cr4 & (1UL << 5))  != 0; // CR4.PAE
    const bool longmode = sregs !is null && (sregs.efer & (1UL << 10)) != 0; // EFER.LMA
    if (paged && pae && !longmode) return false;          // PAE (3-level) not yet supported
    const ulong cr3     = sregs !is null ? sregs.cr3 : 0;
    // Linear address of the faulting instruction: CS base + RIP (CS base is 0 in
    // long mode and for flat protected-mode guests).
    const ulong rip = regs.rip + (sregs !is null ? sregs.cs.base : 0);

    // Fetch up to 15 instruction bytes at the linear RIP, translating guest-linear
    // -> guest-physical via the guest page tables when paging is on, then
    // guest-physical -> host via EPT.  Stops at the first untranslatable page.
    ubyte[16] buf = 0; size_t got = 0;
    while (got < 15) {
        const ulong lin = rip + got;
        ulong gpa = lin;
        if (paged && !guestTranslate(vm, cr3, lin, longmode, gpa)) break;
        const ulong hpa = slatLookup(&vm.slat, gpa & ~0xFFFUL);
        if (hpa == 0) break;                              // instruction page not mapped
        auto page = cast(ubyte*)phys_to_virt(hpa);
        ulong off = gpa & 0xFFF;
        while (off < 4096 && got < 15) { buf[got++] = page[off]; ++off; }
    }
    if (got == 0) return false;

    const acc = mmioDecode(buf.ptr, got, longmode);
    if (!acc.valid) return false;
    run.u.mmio.len     = acc.size;
    run.u.mmio.isWrite = acc.isWrite ? 1 : 0;
    if (acc.isWrite) {
        const ulong val = acc.isImm ? cast(ulong) acc.imm : mmioRegValue(regs, acc.reg);
        foreach (k; 0 .. acc.size) run.u.mmio.data[k] = cast(ubyte)(val >> (8 * k));
    }
    return true;
}

// ---------------------------------------------------------------------------
// Boot self-test: drive the decoder with synthetic encodings.  No hardware.
// ---------------------------------------------------------------------------
private __gshared uint g_mmioTestFails = 0;
private void mtCheck(bool ok, const(char)* name) {
    if (!ok) { ++g_mmioTestFails; klog("[mmio] selftest FAIL: "); klog(name); klog("\n"); }
}

public void mmioDecodeSelfTest() @nogc nothrow {
    g_mmioTestFails = 0;

    // mov [rax], ebx        89 18   -> write, size 4, reg EBX(3), len 2
    { ubyte[3] b = [0x89, 0x18, 0x00];
      auto a = mmioDecode(b.ptr, 2, true);
      mtCheck(a.valid && a.isWrite && a.size == 4 && a.reg == 3 && a.insnLen == 2, "mov-mem-r32"); }

    // mov ebx, [rax]        8B 18   -> read, size 4, reg EBX(3), len 2
    { ubyte[3] b = [0x8B, 0x18, 0x00];
      auto a = mmioDecode(b.ptr, 2, true);
      mtCheck(a.valid && !a.isWrite && a.size == 4 && a.reg == 3 && a.insnLen == 2, "mov-r32-mem"); }

    // mov byte [rax], 0x5A  C6 00 5A -> write, size 1, imm 0x5A, len 3
    { ubyte[3] b = [0xC6, 0x00, 0x5A];
      auto a = mmioDecode(b.ptr, 3, true);
      mtCheck(a.valid && a.isWrite && a.size == 1 && a.isImm && a.imm == 0x5A && a.insnLen == 3, "mov-mem-imm8"); }

    // mov dword [rcx], 0x12345678  C7 01 78 56 34 12 -> write, size 4, imm, len 6
    { ubyte[6] b = [0xC7, 0x01, 0x78, 0x56, 0x34, 0x12];
      auto a = mmioDecode(b.ptr, 6, true);
      mtCheck(a.valid && a.isWrite && a.size == 4 && a.isImm && a.imm == 0x12345678 && a.insnLen == 6, "mov-mem-imm32"); }

    // mov rax, [rbx]        48 8B 03 -> read, size 8 (REX.W), reg RAX(0), len 3
    { ubyte[3] b = [0x48, 0x8B, 0x03];
      auto a = mmioDecode(b.ptr, 3, true);
      mtCheck(a.valid && !a.isWrite && a.size == 8 && a.reg == 0 && a.insnLen == 3, "mov-r64-mem-rexw"); }

    // mov [rax], bx         66 89 18 -> write, size 2 (0x66), reg BX(3), len 3
    { ubyte[3] b = [0x66, 0x89, 0x18];
      auto a = mmioDecode(b.ptr, 3, true);
      mtCheck(a.valid && a.isWrite && a.size == 2 && a.reg == 3 && a.insnLen == 3, "mov-mem-r16-66"); }

    // movzx eax, byte [rdx] 0F B6 02 -> read, size 1, zeroExtend, reg EAX(0), len 3
    { ubyte[3] b = [0x0F, 0xB6, 0x02];
      auto a = mmioDecode(b.ptr, 3, true);
      mtCheck(a.valid && !a.isWrite && a.size == 1 && a.zeroExtend && a.reg == 0 && a.insnLen == 3, "movzx-r-mem8"); }

    // mov [rax+4], ebx      89 58 04 -> write, size 4, reg EBX(3), disp8, len 3
    { ubyte[3] b = [0x89, 0x58, 0x04];
      auto a = mmioDecode(b.ptr, 3, true);
      mtCheck(a.valid && a.isWrite && a.size == 4 && a.reg == 3 && a.insnLen == 3, "mov-mem-disp8"); }

    // mov [rax+rcx], ebx    89 1C 08 -> write, size 4, reg EBX(3), SIB, len 3
    { ubyte[3] b = [0x89, 0x1C, 0x08];
      auto a = mmioDecode(b.ptr, 3, true);
      mtCheck(a.valid && a.isWrite && a.size == 4 && a.reg == 3 && a.insnLen == 3, "mov-mem-sib"); }

    // mov [rip+disp32], ebx 89 1D xx xx xx xx -> write, size 4, disp32, len 6
    { ubyte[6] b = [0x89, 0x1D, 0x00, 0x10, 0x00, 0x00];
      auto a = mmioDecode(b.ptr, 6, true);
      mtCheck(a.valid && a.isWrite && a.size == 4 && a.reg == 3 && a.insnLen == 6, "mov-mem-riprel"); }

    // mov r8d, [r9]         45 8B 01 -> read, size 4, reg R8(8, REX.R), len 3
    { ubyte[3] b = [0x45, 0x8B, 0x01];
      auto a = mmioDecode(b.ptr, 3, true);
      mtCheck(a.valid && !a.isWrite && a.size == 4 && a.reg == 8 && a.insnLen == 3, "mov-r8d-mem-rexr"); }

    // NEGATIVE: mov eax, ebx  89 D8 (mod==3, register-direct) -> invalid
    { ubyte[2] b = [0x89, 0xD8];
      auto a = mmioDecode(b.ptr, 2, true);
      mtCheck(!a.valid, "reg-direct-rejected"); }

    // NEGATIVE: add [rax], ebx  01 18 (not a MOV) -> invalid
    { ubyte[2] b = [0x01, 0x18];
      auto a = mmioDecode(b.ptr, 2, true);
      mtCheck(!a.valid, "non-mov-rejected"); }

    // NEGATIVE: C7 with reg != 0 (not MOV /0) -> invalid  (C7 /1 = ??, F7-like ext)
    { ubyte[6] b = [0xC7, 0x08, 0x00, 0x00, 0x00, 0x00];
      auto a = mmioDecode(b.ptr, 6, true);
      mtCheck(!a.valid, "c7-nonzero-reg-rejected"); }

    // NEGATIVE: truncated (opcode only) -> invalid
    { ubyte[1] b = [0x89];
      auto a = mmioDecode(b.ptr, 1, true);
      mtCheck(!a.valid, "truncated-rejected"); }

    if (g_mmioTestFails == 0)
        klog("[mmio] decode selftest PASS (mov r/m<->r, imm, movzx/sx, disp/sib/riprel, rex; reg-direct+non-mov rejected)\n");
    else
        klog("[mmio] decode selftest FAILURES logged above\n");
}

// ---------------------------------------------------------------------------
// Boot self-test for the guest page-table walker: build a minimal long-mode
// 4-level table in EPT-mapped guest RAM and assert translations.  No guest
// execution — pure walk over tables we author.
// ---------------------------------------------------------------------------
public void mmioPagedWalkSelfTest() @nogc nothrow {
    import core.virt.kvm : kvmCreateVm;
    import core.virt.vm  : vmCheck, kvmUnpackHandle, kvmVmFdClosed;
    import core.virt.slat : slatMap;
    import memory.mm : alloc_phys_page;
    import core.exports : g_current_task_id;

    const long vh = kvmCreateVm(cast(int)g_current_task_id);
    if (vh < 0) { klog("[mmio] paged-walk: kvmCreateVm failed\n"); return; }
    uint vo, vg; kvmUnpackHandle(cast(ulong)vh, vo, vg);
    Vm* vm = vmCheck(vo, vg);
    if (vm is null) { klog("[mmio] paged-walk: vmCheck null\n"); return; }

    // Page-table pages at guest-physical 0x1000..0x4000, each EPT-mapped so the
    // walker (which reads through EPT) can fetch entries.
    ulong[4] tgpa = [0x1000, 0x2000, 0x3000, 0x4000];
    ulong[4] host = [0, 0, 0, 0];
    foreach (i; 0 .. 4) {
        const ulong ph = alloc_phys_page();
        if (ph == 0 || !slatMap(&vm.slat, tgpa[i], ph, 1 | 2 | 4)) {
            klog("[mmio] paged-walk: map fail\n"); kvmVmFdClosed(vo, vg); return;
        }
        auto p = cast(ubyte*)phys_to_virt(ph);
        foreach (j; 0 .. 4096) p[j] = 0;
        host[i] = cast(ulong)p;
    }
    auto pml4 = cast(ulong*)host[0];
    auto pdpt = cast(ulong*)host[1];
    auto pd   = cast(ulong*)host[2];
    auto pt   = cast(ulong*)host[3];

    uint fails = 0;

    // Case 1: 4KB mapping.  lin 0x400000 -> gpa 0x5000.
    const ulong lin1 = 0x400000;
    pml4[(lin1 >> 39) & 0x1FF] = 0x2000 | PTE_P;
    pdpt[(lin1 >> 30) & 0x1FF] = 0x3000 | PTE_P;
    pd  [(lin1 >> 21) & 0x1FF] = 0x4000 | PTE_P;
    pt  [(lin1 >> 12) & 0x1FF] = 0x5000 | PTE_P;
    ulong g1;
    if (!(guestTranslate(vm, 0x1000, lin1, true, g1) && g1 == (0x5000 | (lin1 & 0xFFF)))) ++fails;

    // Case 2: 2MB large page.  lin 0x600010 -> 0x200000 | offset.
    const ulong lin2 = 0x600010;
    pdpt[(lin2 >> 30) & 0x1FF] = 0x3000 | PTE_P;              // (same PDPT slot as case 1)
    pd  [(lin2 >> 21) & 0x1FF] = 0x200000 | PTE_P | PTE_PS;   // 2MB page
    ulong g2;
    if (!(guestTranslate(vm, 0x1000, lin2, true, g2) && g2 == (0x200000 | (lin2 & 0x001F_FFFF)))) ++fails;

    // Case 3: not-present PD slot -> translation fails.
    ulong g3;
    if (guestTranslate(vm, 0x1000, 0x800000, true, g3)) ++fails;   // pd[4] == 0

    if (fails == 0)
        klog("[mmio] paged-walk selftest PASS (4-level: 4K + 2M large page + not-present)\n");
    else
        klog("[mmio] paged-walk selftest FAIL\n");
    kvmVmFdClosed(vo, vg);
}
