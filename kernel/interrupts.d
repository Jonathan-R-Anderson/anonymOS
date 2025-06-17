// kernel/interrupts.d

module kernel.interrupts;

import kernel.types : Registers, ErrorCode;
import kernel.io : inb, outb;
import kernel.terminal : terminal_writestring, terminal_write_hex, terminal_putchar; // scancode_to_char is used in kernel.keyboard
import kernel.panic : kernel_panic;

public: // Export interrupt_handler_d, pic_remap

// PIC Constants
enum PIC1_COMMAND = 0x20;
enum PIC1_DATA = 0x21;
enum PIC2_COMMAND = 0xA0;
enum PIC2_DATA = 0xA1;
enum PIC_EOI = 0x20; // End Of Interrupt command code

void pic_remap(int offset1, int offset2) {
    ubyte a1, a2;
    a1 = inb(PIC1_DATA);
    a2 = inb(PIC2_DATA);

    outb(PIC1_COMMAND, 0x11);
    outb(PIC2_COMMAND, 0x11);

    outb(PIC1_DATA, cast(ubyte)offset1);
    outb(PIC2_DATA, cast(ubyte)offset2);

    outb(PIC1_DATA, 4);
    outb(PIC2_DATA, 2);
    outb(PIC1_DATA, 0x01);
    outb(PIC2_DATA, 0x01);

    outb(PIC1_DATA, a1);
    outb(PIC2_DATA, a2);
}

// The assembly stub will pass:
// %rdi: pointer to saved GPRs (Registers* regs_ptr)
// %rsi: interrupt number (ulong int_no)
// %rdx: error code (ulong err_code)
extern (C) void interrupt_handler_d(Registers* regs_ptr, ulong int_no, ulong err_code_val) {
    // Send EOI (End Of Interrupt) to PICs
    // IRQs are from 32 to 47
    if (int_no >= 32 && int_no <= 47) {
        if (int_no >= 40) { // IRQs 8-15 are on slave PIC (remapped to 40-47)
            outb(PIC2_COMMAND, PIC_EOI); // Slave PIC
        }
        outb(PIC1_COMMAND, PIC_EOI); // Master PIC
    }

    // --- Logging the interrupt ---
    terminal_writestring("Interrupt: ");
    terminal_write_hex(int_no);

    // Check if the CPU pushed an error code for this exception type
    bool has_cpu_error_code = (int_no == 8 || (int_no >= 10 && int_no <= 14) || int_no == 17 || int_no == 21 || int_no == 29 || int_no == 30);
    if (has_cpu_error_code) {
        terminal_writestring(", Error Code: ");
        terminal_write_hex(err_code_val);
    }
    terminal_putchar('\n');

    // --- Handling specific CPU exceptions ---
    // Note: Interrupt 33 (Keyboard) is now handled by keyboard_handler_asm.s
    // and kernel.keyboard.keyboard_interrupt_handler, so it's not processed here.
    if (int_no < 32 && int_no != 1 && int_no != 3 && int_no != 33) { // CPU Exception (excluding debug/breakpoint and keyboard)
        if (int_no == 13) { // GPF
            terminal_writestring("General Protection Fault! Selector: ");
            terminal_write_hex(err_code_val); // Error code for GPF is selector
            terminal_putchar('\n');
        } else if (int_no == 14) { // Page Fault
            terminal_writestring("Page Fault! Details: ");
            terminal_write_hex(err_code_val); // Error code for Page Fault has details
            ulong fault_addr; // Changed from uint to ulong for 64-bit CR2
            asm { "mov %%cr2, %0" : "=r"(fault_addr); }
            terminal_writestring(" Addr: ");
            terminal_write_hex(fault_addr); // Ensure this function can handle ulong
            terminal_putchar('\n');
        }
        if (int_no != 2) { // Don't panic on NMI for now, just log it.
            kernel_panic("CPU Exception Encountered.", cast(ErrorCode)int_no);
        }
    }
}