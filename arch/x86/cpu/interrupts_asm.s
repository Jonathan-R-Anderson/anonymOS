; isr_stubs.s
extern interrupt_handler_d ; D language interrupt handler

; Macro to generate ISR stubs that don't push an error code
%macro ISR_NOERRCODE 1
  global isr%1
  isr%1:
    cli             ; Disable interrupts
    push dword 0    ; Push a dummy error code (32-bit)
    push dword %1   ; Push the interrupt number (32-bit)
    jmp isr_common_stub
%endmacro

; Macro to generate ISR stubs that do push an error code
%macro ISR_ERRCODE 1
  global isr%1
  isr%1:
    cli             ; Disable interrupts
    ; Error code is already on stack
    push dword %1   ; Push the interrupt number (32-bit)
    jmp isr_common_stub
%endmacro

; CPU Exceptions (ISRs 0-31)
ISR_NOERRCODE 0   ; Divide by zero
ISR_NOERRCODE 1   ; Debug
ISR_NOERRCODE 2   ; Non-maskable interrupt
ISR_NOERRCODE 3   ; Breakpoint
ISR_NOERRCODE 4   ; Overflow
ISR_NOERRCODE 5   ; Bound range exceeded
ISR_NOERRCODE 6   ; Invalid opcode
ISR_NOERRCODE 7   ; Device not available
ISR_ERRCODE   8   ; Double fault
ISR_NOERRCODE 9   ; Coprocessor segment overrun (unused)
ISR_ERRCODE   10  ; Invalid TSS
ISR_ERRCODE   11  ; Segment not present
ISR_ERRCODE   12  ; Stack-segment fault
ISR_ERRCODE   13  ; General protection fault
ISR_ERRCODE   14  ; Page fault
ISR_NOERRCODE 15  ; Reserved
ISR_NOERRCODE 16  ; x87 FPU floating-point error
ISR_ERRCODE   17  ; Alignment check
ISR_NOERRCODE 18  ; Machine check
ISR_NOERRCODE 19  ; SIMD floating-point exception
ISR_NOERRCODE 20  ; Virtualization exception
ISR_NOERRCODE 21  ; Control protection exception
; ISRs 22-31 are reserved
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

; Hardware IRQs (ISRs 32-47 after remapping)
ISR_NOERRCODE 32  ; IRQ0: Programmable Interval Timer
ISR_NOERRCODE 33  ; IRQ1: Keyboard
ISR_NOERRCODE 34  ; IRQ2: Cascade for 8259A Slave controller
ISR_NOERRCODE 35  ; IRQ3: COM2
ISR_NOERRCODE 36  ; IRQ4: COM1
ISR_NOERRCODE 37  ; IRQ5: LPT2
ISR_NOERRCODE 38  ; IRQ6: Floppy disk
ISR_NOERRCODE 39  ; IRQ7: LPT1 / Spurious
ISR_NOERRCODE 40  ; IRQ8: CMOS real-time clock
ISR_NOERRCODE 41  ; IRQ9: Free for peripherals / SCSI / NIC
ISR_NOERRCODE 42  ; IRQ10: Free for peripherals / SCSI / NIC
ISR_NOERRCODE 43  ; IRQ11: Free for peripherals / SCSI / NIC
ISR_NOERRCODE 44  ; IRQ12: PS/2 mouse
ISR_NOERRCODE 45  ; IRQ13: FPU / Coprocessor / Inter-processor
ISR_NOERRCODE 46  ; IRQ14: Primary ATA hard disk
ISR_NOERRCODE 47  ; IRQ15: Secondary ATA hard disk

; Common ISR stub
isr_common_stub:
    pusha       ; Push all general purpose registers (eax, ecx, edx, ebx, original esp, ebp, esi, edi)

    mov ax, ds  ; Get current data segment selector
    push eax    ; Save it on the stack (ds is 16 bits, but push eax pushes 32 bits)

    mov ax, 0x10 ; Load kernel data segment selector (0x10, see GDT setup)
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    ; ss is already kernel stack segment

    cld          ; Clear direction flag (good practice for C/D calls)

    ; Pass a pointer to the register structure to the D handler.
    ; ESP currently points to the saved original 'ds'.
    ; The D handler's `Registers* regs` argument will point to this location.
    mov eax, esp
    push eax    ; Push pointer to stack frame (argument for interrupt_handler_d)
    call interrupt_handler_d ; Call the D handler
    add esp, 4  ; Clean up the pushed pointer argument (cdecl convention)

    pop eax     ; Restore original data segment selector (eax gets the value from stack)
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax

    popa        ; Pop all general purpose registers
    add esp, 8  ; Clean up the error code and interrupt number pushed by specific ISR
    ; sti       ; Re-enable interrupts. Note: iret will restore EFLAGS, including IF.
                ; It's generally safer to let iret handle this.
    iret        ; Return from interrupt (pops CS, EIP, EFLAGS, and SS, ESP if privilege change)

; A simple way to make other ISRs point to a generic handler if not specifically handled
global unhandled_interrupt
unhandled_interrupt:
    ; You could print an "unhandled interrupt" message here if desired
    iret

; Add this section to prevent executable stack warnings.
section .note.GNU-stack noalloc noexec nowrite progbits

; Add this section to prevent executable stack warnings.
section .note.GNU-stack noalloc noexec nowrite progbits