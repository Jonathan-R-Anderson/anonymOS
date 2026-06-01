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
