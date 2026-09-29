/*
 * guest.s -- smallest guest Cloud Hypervisor v54 can boot with --kernel.
 * Pure GNU as (no cpp).  Assembled as ELF64 (--64) with .code32 code,
 * exactly like Linux's own PVH entry (arch/x86/platform/pvh/head.S).
 *
 * Boot protocol = Xen PVH as implemented by CH + linux-loader 0.14.0:
 *   - ELF64 only: e_phentsize must be sizeof(Elf64_Phdr)=56 (elf/mod.rs:154)
 *   - e_entry must be >= 0x100000 = HIGH_RAM_START       (elf/mod.rs:221-225)
 *   - each PT_LOAD is copied (p_filesz bytes) to p_paddr  (elf/mod.rs:254-294)
 *   - PT_NOTE "Xen\0", type 18 (XEN_ELFNOTE_PHYS32_ENTRY), desc = u32 entry
 *     (elf/mod.rs:312-411); no note => KernelMissingPvhHeader (vm.rs:1680)
 *   - vCPU entry state (arch/src/x86_64/regs.rs:111-127, 165-210):
 *       32-bit protected mode, paging off, CR0=PE, CR4=0, EFLAGS=0x2 (IF=0),
 *       CS=0x08 flat 4 GiB code32, DS/ES/FS/GS/SS=0x10 flat 4 GiB data,
 *       EBX=0x6000 (struct hvm_start_info), ESP=0 (NOT set for PVH),
 *       IDT base 0x520 limit 7 (no handlers: the guest must not fault).
 *
 * Output: COM1 16550 model on I/O port 0x3f8 (vmm/src/device_manager.rs:2181-2218),
 * byte-wide accesses only (devices/src/legacy/serial.rs:287-325).  CH's LSR
 * always reports THRE|TEMT (serial.rs:50), so the LSR poll below succeeds on
 * the first read; it is bounded so a broken IN completion can never wedge us.
 *
 * EXIT_MODE (as --defsym EXIT_MODE=n):
 *   0 = cli; hlt loop   (default; parks forever on a KVM with in-kernel HLT)
 *   1 = ACPI S5 poweroff: outb 0x34 -> port 0x600 (CH AcpiShutdownDevice,
 *       devices/src/acpi.rs:76-84) => CH exits 0; cli; hlt fallback
 *   2 = pause; jmp spin (no VM exit of any kind after the message)
 */

        .ifndef EXIT_MODE
        .set    EXIT_MODE, 0
        .endif

        .set    COM1,            0x3f8
        .set    COM1_LSR,        0x3fd
        .set    LSR_THRE,        0x20
        .set    LSR_POLL_MAX,    0x100        /* worst case 256 IN exits per byte */
        .set    PVH_MAGIC,       0x336ec578   /* XEN_HVM_START_MAGIC_VALUE (arch/src/x86_64/mod.rs:1344) */
        .set    ACPI_SLEEP_CTL,  0x600
        .set    ACPI_S5,         0x34         /* (5 << 2) | (1 << 5) */

        .code32
        .section .text.entry, "ax", @progbits
        .globl  pvh_start
        .type   pvh_start, @function
pvh_start:
        cli
        cld
        movl    $stack_top, %esp             /* CH leaves ESP=0 on the PVH path */
        movl    %ebx, %ebp                   /* hvm_start_info* (0x6000) */

        movl    $msg_hello, %esi
        movl    $msg_hello_len, %ecx
        call    puts

        /* 2nd line: is the VMM-written hvm_start_info visible through guest RAM? */
        movl    $msg_ok, %esi
        movl    $msg_ok_len, %ecx
        cmpl    $PVH_MAGIC, (%ebp)
        je      1f
        movl    $msg_bad, %esi
        movl    $msg_bad_len, %ecx
1:      call    puts

        .if EXIT_MODE == 1
        movw    $ACPI_SLEEP_CTL, %dx
        movb    $ACPI_S5, %al
        outb    %al, %dx
        .endif

        .if EXIT_MODE == 2
2:      pause
        jmp     2b
        .else
3:      cli
        hlt
        jmp     3b
        .endif

/* puts: ESI = buffer, ECX = length.  Clobbers EAX, EBX, ECX, EDX, ESI. */
puts:
        jecxz   9f
4:      movl    $LSR_POLL_MAX, %ebx
5:      movw    $COM1_LSR, %dx
        inb     %dx, %al
        testb   $LSR_THRE, %al
        jnz     6f
        decl    %ebx
        jnz     5b
6:      movw    $COM1, %dx
        lodsb
        outb    %al, %dx
        loop    4b
9:      ret

        .section .rodata, "a", @progbits
msg_hello:
        .ascii  "HELLO FROM CH GUEST\n"
        .set    msg_hello_len, . - msg_hello
msg_ok:
        .ascii  "pvh start_info magic OK\n"
        .set    msg_ok_len, . - msg_ok
msg_bad:
        .ascii  "pvh start_info magic BAD\n"
        .set    msg_bad_len, . - msg_bad

        .section .bss, "aw", @nobits
        .balign 16
        .skip   256
stack_top:

/* Xen PVH entry note.  Allocated ("a") so it sits in the PT_LOAD too, as in Linux. */
        .section .note.Xen, "a", @note
        .balign 4
        .long   8f - 7f                      /* n_namesz = 4 ("Xen\0") */
        .long   11f - 10f                    /* n_descsz = 4 */
        .long   18                           /* n_type   = XEN_ELFNOTE_PHYS32_ENTRY */
7:      .asciz  "Xen"
8:      .balign 4
10:     .long   pvh_start                    /* 32-bit physical entry */
11:     .balign 4
