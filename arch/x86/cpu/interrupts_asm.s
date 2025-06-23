# interrupts_asm.s (AT&T syntax, 64-bit)
.extern interrupt_handler_d # D language interrupt handler

# Macro to generate ISR stubs that don't push an error code
.macro ISR_NOERRCODE num
  .global isr\num
  isr\num:
    cli             # Disable interrupts
    pushq $0        # Push a dummy error code (64-bit)
    pushq $\num     # Push the interrupt number (64-bit)

    jmp isr_common_stub
.endm

# Macro to generate ISR stubs that do push an error code (CPU pushes it)
.macro ISR_ERRCODE num
  .global isr\num
  isr\num:
    cli             # Disable interrupts
    # Error code is already on stack (pushed by CPU as 64-bit value in long mode)
    pushq $\num     # Push the interrupt number (64-bit)
 
    jmp isr_common_stub

.endm

.section .text
.code64             # Assemble for 64-bit mode

# CPU Exceptions (ISRs 0-31)
ISR_NOERRCODE 0   # Divide by zero
ISR_NOERRCODE 1   # Debug
ISR_NOERRCODE 2   # Non-maskable interrupt
ISR_NOERRCODE 3   # Breakpoint
ISR_NOERRCODE 4   # Overflow
ISR_NOERRCODE 5   # Bound range exceeded (BOUND instruction invalid in 64-bit, but exception can occur)
ISR_NOERRCODE 6   # Invalid opcode
ISR_NOERRCODE 7   # Device not available
ISR_ERRCODE   8   # Double fault
ISR_NOERRCODE 9   # Coprocessor segment overrun (legacy)
ISR_ERRCODE   10  # Invalid TSS
ISR_ERRCODE   11  # Segment not present
ISR_ERRCODE   12  # Stack-segment fault
ISR_ERRCODE   13  # General protection fault
ISR_ERRCODE   14  # Page fault
ISR_NOERRCODE 15  # Reserved
ISR_NOERRCODE 16  # x87 FPU floating-point error
ISR_ERRCODE   17  # Alignment check
ISR_NOERRCODE 18  # Machine check
ISR_NOERRCODE 19  # SIMD floating-point exception
ISR_NOERRCODE 20  # Virtualization exception
ISR_NOERRCODE 21  # Control protection exception
# ISRs 22-31 are reserved
ISR_NOERRCODE 22
ISR_NOERRCODE 23
ISR_NOERRCODE 24
ISR_NOERRCODE 25
ISR_NOERRCODE 26
ISR_NOERRCODE 27
ISR_NOERRCODE 28
ISR_NOERRCODE 29
ISR_NOERRCODE 30
ISR_NOERRCODE 31

# Hardware IRQs (ISRs 32-47 after remapping)
ISR_NOERRCODE 33  # IRQ1: Keyboard
ISR_NOERRCODE 34  # IRQ2: Cascade for 8259A Slave controller
ISR_NOERRCODE 35  # IRQ3: COM2
ISR_NOERRCODE 36  # IRQ4: COM1
ISR_NOERRCODE 37  # IRQ5: LPT2
ISR_NOERRCODE 38  # IRQ6: Floppy disk
ISR_NOERRCODE 39  # IRQ7: LPT1 / Spurious
ISR_NOERRCODE 40  # IRQ8: CMOS real-time clock
ISR_NOERRCODE 41  # IRQ9: Free for peripherals / SCSI / NIC
ISR_NOERRCODE 42  # IRQ10: Free for peripherals / SCSI / NIC
ISR_NOERRCODE 43  # IRQ11: Free for peripherals / SCSI / NIC
ISR_NOERRCODE 44  # IRQ12: PS/2 mouse
ISR_NOERRCODE 45  # IRQ13: FPU / Coprocessor / Inter-processor
ISR_NOERRCODE 46  # IRQ14: Primary ATA hard disk
ISR_NOERRCODE 47  # IRQ15: Secondary ATA hard disk


.global isr32
isr32:
    cli
    pushq $0  # Dummy error code
    pushq $32 # IRQ vector number (0x20)
    jmp isr_common_stub

# Common ISR stub
# The stack frame passed to the D handler (via %rdi pointing to it) will look like:
# [lowest address on stack for this structure]
#   %rax
#   %rbx
#   %rcx
#   %rdx
#   %rbp
#   %rsi
#   %rdi
#   %r8
#   %r9
#   %r10
#   %r11
#   %r12
#   %r13
#   %r14
#   %r15
#   (interrupt number and error code are *above* this structure on the stack,
#    and the CPU-pushed state is even further above that.
#    The D `Registers` struct should reflect the GPRs, int_no, err_code, and CPU state)
# For simplicity, we'll pass %rsp to the D handler, which will point to the
# last pushed GPR (%r15). The D struct will then need to be defined carefully.
# A more robust way is to allocate space on stack and fill it, then pass pointer.
# For now, let's push GPRs, then set up segments, then call.


isr_common_stub:
    # Save general purpose registers.
    # The D 'Registers' struct must match this order.
    pushq %rax
    pushq %rbx
    pushq %rcx
    pushq %rdx
    pushq %rsi
    pushq %rdi
    pushq %rbp
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15

    # In 64-bit mode, segment registers DS, ES, SS are less critical.
    # FS and GS might be used (e.g., for TLS or CPU-specific data).
    # We'll set DS, ES to kernel data segment.
    movw $0x10, %ax     # Kernel Data Segment Selector (from GDT)
    movw %ax, %ds
    movw %ax, %es
    # movw $0x00, %ax   # Example if FS/GS should be NULL
    # movw %ax, %fs
    # movw %ax, %gs

    cld                 # Clear direction flag

    # Arguments for interrupt_handler_d(Registers* regs_ptr, ulong int_no, ulong err_code_val)
    # %rdi: pointer to saved GPRs
    # %rsp now points to the saved %r15. This is what the D handler will receive.
    movq %rsp, %rdi     # First argument to D function is in %rdi

    # The interrupt number and error code were pushed by the ISR stubs *before*
    # the general purpose registers. They sit just below the register save area
    # on the stack. Do not pop them here, simply load their values.
    movq 120(%rsp), %rsi    # Second argument: int_no
    movq 128(%rsp), %rdx    # Third argument: err_code
    subq $8, %rsp           # Align stack before C call
    call interrupt_handler_d
    addq $8, %rsp           # Remove alignment padding
    # Restore general purpose registers (in reverse order of push)
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rbp
    popq %rdi
    popq %rsi
    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax
    # Remove the pushed interrupt number and error code so iretq sees the CPU frame
    addq $16, %rsp
    iretq               # Return from interrupt


.extern kernel_panic

.section .rodata
unhandled_msg:
    .string "Unhandled Interrupt"

.section .text
.global unhandled_interrupt

unhandled_interrupt:
    cli
    leaq unhandled_msg(%rip), %rdi   # message pointer
    movl $0, %esi                    # error code
    call kernel_panic
1:
    hlt
    jmp 1b

.global default_isr
.extern default_isr_handler

default_isr:
    call default_isr_handler
    cli
1:  hlt
    jmp 1b


.section .note.GNU-stack, "", @progbits # Mark stack as non-executable
