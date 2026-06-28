.global loadIdt
loadIdt:
    lidt (%rdi)
    ret

.global loadGdt
loadGdt:
    lgdt (%rdi)
    pushq $0x08
    lea 1f(%rip), %rax
    pushq %rax
    lretq
1:
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov %ax, %ss
    ret

.global loadTr
loadTr:
    ltr %di
    ret

# SMP_ROADMAP S4.2: the AP's #BP (int3) handler.  Reached via the AP's IST1 stack (its own
# per-CPU TSS stack).  GS base = &g_percpu[thisCpu], so %gs:48 is that CPU's PerCpu.bpHandled
# (offset asserted in kmain.d).  Immediate→memory, so NO register is clobbered — just set the
# flag and iretq (#BP pushes no error code).
.global apBpHandler
apBpHandler:
    movq $1, %gs:48
    iretq

# Safe catch-all for every other AP vector: halt this AP (never triple-fault the VM).
.global apDefaultHandler
apDefaultHandler:
    cli
1:  hlt
    jmp 1b

# SMP_ROADMAP S4.3: set up THIS CPU's own syscall MSRs (per-CPU MSRs, so the BSP is untouched).
# Mirrors the BSP's setupSysCalls exactly, except LSTAR points at apSyscallStub.
.global setupApSyscall
setupApSyscall:
    # STAR: SYSCALL CS/SS = 0x08/0x10; SYSRET base = 0x10
    movq  $0xC0000081, %rcx
    movl  $0x0, %eax
    movl  $0x00100008, %edx
    wrmsr
    # LSTAR: this AP's 64-bit syscall entry point
    movq  $0xC0000082, %rcx
    movabsq $apSyscallStub, %rax
    movq  %rax, %rdx
    shrq  $32, %rdx
    wrmsr
    # SFMASK: same mask the BSP uses (TF/IF/DF/IOPL/NT/AC)
    movq  $0xC0000084, %rcx
    movl  $0x47700, %eax
    movl  $0, %edx
    wrmsr
    # EFER: set SCE (bit 0), preserve the rest
    movq  $0xC0000080, %rcx
    rdmsr
    orl   $0x1, %eax
    wrmsr
    ret

# The AP's own syscall entry.  On `syscall`: RCX = return RIP, R11 = saved RFLAGS, CS/SS =
# kernel (from STAR).  GS base = &g_percpu[thisCpu], so %gs:56 is that CPU's PerCpu.syscallSeen
# (offset asserted in kmain.d).  Record entry, restore RFLAGS, and return to the caller.
.global apSyscallStub
apSyscallStub:
    movq  $1, %gs:56
    pushq %r11
    popfq
    jmpq  *%rcx

# CPL0 self-test driver: executes `syscall`; apSyscallStub's `jmp *rcx` returns control to the
# `ret` below (RCX = the instruction after `syscall`), which returns to the D caller.
.global apDoSyscall
apDoSyscall:
    syscall
    ret

# SMP_ROADMAP S5: set up THIS CPU's own local-APIC timer via x2APIC (MSRs — no MMIO map needed).
# Per-CPU MSRs, so the BSP's PIC/PIT is untouched.  Periodic timer → vector 0x20 → apTimerHandler.
.global setupApTimer
setupApTimer:
    # IA32_APIC_BASE (0x1B): set bit 10 (x2APIC) + bit 11 (global enable), preserve the base.
    movl  $0x1B, %ecx
    rdmsr
    orl   $0xC00, %eax
    wrmsr
    # Spurious Interrupt Vector (x2APIC MSR 0x80F): vector 0xFF + bit 8 (APIC software-enable).
    movl  $0x80F, %ecx
    movl  $0x1FF, %eax
    xorl  %edx, %edx
    wrmsr
    # Divide Configuration (0x83E): divide by 16 (encoding 0b0011).
    movl  $0x83E, %ecx
    movl  $0x3, %eax
    xorl  %edx, %edx
    wrmsr
    # LVT Timer (0x832): vector 0x20 + periodic mode (bit 17).  Unmasked (bit 16 = 0).
    movl  $0x832, %ecx
    movl  $0x20020, %eax
    xorl  %edx, %edx
    wrmsr
    # Initial Count (0x838): start the periodic countdown (period ≈ count × 16 / apic_freq).
    movl  $0x838, %ecx
    movl  $0x800000, %eax
    xorl  %edx, %edx
    wrmsr
    ret

# The AP's local-APIC timer handler.  Reached via the AP IDT vector 0x20 on IST1 (so it lands on
# the AP's own stack regardless of ring).  GS base = the per-CPU area, so %gs:64 is PerCpu.apicTicks
# (offset asserted in kmain.d).  Bump the tick, EOI the x2APIC (MSR 0x80B = 0), iretq.  An interrupt
# (not an exception) pushes no error code.
.global apTimerHandler
apTimerHandler:
    pushq %rax
    pushq %rcx
    pushq %rdx
    incq  %gs:64
    movl  $0x80B, %ecx
    xorl  %eax, %eax
    xorl  %edx, %edx
    wrmsr
    popq  %rdx
    popq  %rcx
    popq  %rax
    iretq

# Spurious-interrupt handler (vector 0xFF): no EOI needed for a spurious — just return.
.global apSpuriousHandler
apSpuriousHandler:
    iretq

.global x64ReadCR2
x64ReadCR2:
    mov %cr2, %rax
    ret

.global x64ReadCR3
x64ReadCR3:
    mov %cr3, %rax
    ret

.global x64WriteCR3
x64WriteCR3:
    mov %rdi, %cr3
    ret

# Invalidate a single page's TLB entry (much cheaper than a full CR3 reload).
.global x64Invlpg
x64Invlpg:
    invlpg (%rdi)
    ret

.global x64ReadCR0
x64ReadCR0:
    mov %cr0, %rax
    ret

.global x64WriteCR0
x64WriteCR0:
    mov %rdi, %cr0
    ret

.global x64ReadCR4
x64ReadCR4:
    mov %cr4, %rax
    ret

.global x64WriteCR4
x64WriteCR4:
    mov %rdi, %cr4
    ret
