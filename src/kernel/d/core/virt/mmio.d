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
