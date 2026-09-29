#!/usr/bin/env python3
"""check.py -- offline acceptance test for the CH PVH guest (no VM is booted).

1. Re-implements linux-loader 0.14.0 Elf::load + parse_elf_note (loader/elf/mod.rs:142-411)
   with CH's arguments (kernel_offset=None, highmem_start=0x100000; vmm/src/vm.rs:1650-1655)
   and prints what CH would decide (PVH entry / error).
2. Loads the PT_LOADs into a fake guest RAM, writes hvm_start_info.magic at 0x6000
   (arch/src/x86_64/mod.rs:1344-1353), sets PVH entry regs (regs.rs:111-118: RIP=entry,
   RBX=0x6000, RSP=0) and interprets the (small, known) 32-bit instruction set the guest
   uses, with CH's 16550 (LSR=0x60, serial.rs:50) and ACPI sleep port 0x600 models.
"""
import struct, sys

HIGH_RAM_START = 0x100000
PVH_INFO_START = 0x6000

def ch_load(path, mem_size):
    f = open(path, 'rb').read()
    eh = f[:64]
    assert eh[:4] == b'\x7fELF', 'InvalidElfMagicNumber'
    assert eh[5] == 1, 'BigEndianElfOnLittle'
    (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize,
     e_phentsize, e_phnum) = struct.unpack_from('<HHIQQQIHHH', eh, 16)
    assert e_phentsize == 56, 'InvalidProgramHeaderSize'
    assert e_phoff >= 64, 'InvalidProgramHeaderOffset'
    assert e_entry >= HIGH_RAM_START, 'InvalidEntryAddress'
    mem = bytearray(mem_size)
    pvh = 'PvhEntryIgnored'
    kernel_end = 0
    for i in range(e_phnum):
        p_type, p_flags, p_off, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = \
            struct.unpack_from('<IIQQQQQQ', f, e_phoff + 56 * i)
        if p_type != 1 or p_filesz == 0:              # not PT_LOAD
            if p_type == 4:                           # PT_NOTE: each one overwrites
                pvh = parse_note(f, p_off, p_filesz)
            continue
        assert p_paddr + p_filesz <= mem_size, 'ReadKernelImage (outside guest RAM)'
        mem[p_paddr:p_paddr + p_filesz] = f[p_off:p_off + p_filesz]
        kernel_end = max(kernel_end, p_paddr + p_memsz)
    return mem, pvh, e_entry, kernel_end

def parse_note(f, off, filesz):
    rd = 0
    while rd < filesz:
        namesz, descsz, ntype = struct.unpack_from('<III', f, off + rd)
        if ntype == 18 and namesz == 4 and f[off + rd + 12: off + rd + 16] == b'Xen\0':
            desc = off + rd + 12 + ((namesz + 3) & ~3)
            if descsz < 4:
                raise AssertionError('InvalidPvhNote')
            return 'PvhEntryPresent(0x%x)' % struct.unpack_from('<I', f, desc)[0]
        rd += 12 + ((namesz + 3) & ~3) + ((descsz + 3) & ~3)
    return 'PvhEntryNotPresent'

def run(mem, rip, max_steps=100000):
    struct.pack_into('<I', mem, PVH_INFO_START, 0x336ec578)
    r = {'eax': 0, 'ebx': PVH_INFO_START, 'ecx': 0, 'edx': 0,
         'esp': 0, 'ebp': 0, 'esi': 0, 'edi': 0}
    zf = False
    out = bytearray(); exits = {'in': 0, 'out': 0}
    rd8 = lambda a: mem[a]
    rd32 = lambda a: struct.unpack_from('<I', mem, a)[0]
    s8 = lambda v: v - 256 if v > 127 else v
    s32 = lambda v: v - (1 << 32) if v & 0x80000000 else v
    for _ in range(max_steps):
        op = mem[rip]
        if op in (0xfa, 0xfc): rip += 1
        elif op == 0xbc: r['esp'] = rd32(rip + 1); rip += 5
        elif op == 0xbe: r['esi'] = rd32(rip + 1); rip += 5
        elif op == 0xb9: r['ecx'] = rd32(rip + 1); rip += 5
        elif op == 0xbb: r['ebx'] = rd32(rip + 1); rip += 5
        elif op == 0xb0: r['eax'] = (r['eax'] & ~0xff) | mem[rip + 1]; rip += 2
        elif op == 0x89 and mem[rip + 1] == 0xdd: r['ebp'] = r['ebx']; rip += 2
        elif op == 0x66 and mem[rip + 1] == 0xba:
            r['edx'] = (r['edx'] & ~0xffff) | struct.unpack_from('<H', mem, rip + 2)[0]; rip += 4
        elif op == 0x81 and mem[rip + 1] == 0x7d and mem[rip + 2] == 0:
            zf = rd32(r['ebp']) == rd32(rip + 3); rip += 7
        elif op == 0xe8:
            ret = rip + 5; r['esp'] -= 4; struct.pack_into('<I', mem, r['esp'], ret)
            rip = (ret + s32(rd32(rip + 1))) & 0xffffffff
        elif op == 0xc3: rip = rd32(r['esp']); r['esp'] += 4
        elif op == 0x74: rip = rip + 2 + (s8(mem[rip + 1]) if zf else 0)
        elif op == 0x75: rip = rip + 2 + (s8(mem[rip + 1]) if not zf else 0)
        elif op == 0xeb: rip = rip + 2 + s8(mem[rip + 1])
        elif op == 0xe3: rip = rip + 2 + (s8(mem[rip + 1]) if r['ecx'] == 0 else 0)
        elif op == 0xe2:
            r['ecx'] = (r['ecx'] - 1) & 0xffffffff
            rip = rip + 2 + (s8(mem[rip + 1]) if r['ecx'] else 0)
        elif op == 0x4b: r['ebx'] = (r['ebx'] - 1) & 0xffffffff; zf = r['ebx'] == 0; rip += 1
        elif op == 0xa8: zf = (r['eax'] & mem[rip + 1]) == 0; rip += 2
        elif op == 0xac: r['eax'] = (r['eax'] & ~0xff) | mem[r['esi']]; r['esi'] += 1; rip += 1
        elif op == 0xec:
            port = r['edx'] & 0xffff; exits['in'] += 1
            v = 0x60 if port == 0x3fd else 0
            r['eax'] = (r['eax'] & ~0xff) | v; rip += 1
        elif op == 0xee:
            port = r['edx'] & 0xffff; al = r['eax'] & 0xff; exits['out'] += 1
            if port == 0x3f8: out.append(al)
            elif port == 0x600 and al == 0x34:
                return out, 'ACPI S5 -> CH guest_exit_evt (clean exit)', exits
            rip += 1
        elif op == 0xf4: return out, 'HLT at 0x%x (IF=0)' % rip, exits
        elif op == 0xf3 and mem[rip + 1] == 0x90:
            return out, 'PAUSE spin at 0x%x' % rip, exits
        else:
            return out, 'UNKNOWN opcode %02x at 0x%x' % (op, rip), exits
    return out, 'step limit', exits

if __name__ == '__main__':
    mem_size = 2 << 20
    for path in sys.argv[1:]:
        mem, pvh, entry, kend = ch_load(path, mem_size)
        print('%s: e_entry=0x%x %s kernel_end=0x%x' % (path, entry, pvh, kend))
        assert pvh.startswith('PvhEntryPresent'), 'CH would fail: KernelMissingPvhHeader'
        rip = int(pvh[len('PvhEntryPresent('):-1], 16)
        out, why, exits = run(mem, rip)
        print('  serial: %r' % out.decode())
        print('  stop:   %s   (port exits: %d IN, %d OUT)' % (why, exits['in'], exits['out']))
