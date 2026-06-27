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
