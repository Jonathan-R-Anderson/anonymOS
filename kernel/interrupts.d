// kernel/interrupts.d

module kernel.interrupts;

import kernel.types : Registers, ErrorCode;
import kernel.io : inb, outb;
import kernel.terminal : terminal_writestring, terminal_write_hex, terminal_putchar;
import kernel.keyboard : scancode_to_char;
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

extern (C) void interrupt_handler_d(Registers* regs) {
    if (regs.int_no >= 32 && regs.int_no <= 47) {
        if (regs.int_no >= 40) {
            outb(PIC2_COMMAND, PIC_EOI);
        }
        outb(PIC1_COMMAND, PIC_EOI);
    }

    terminal_writestring("Interrupt: ");
    terminal_write_hex(regs.int_no);

    bool has_cpu_error_code = (regs.int_no == 8 || (regs.int_no >= 10 && regs.int_no <= 14) || regs.int_no == 17);
    if (has_cpu_error_code) {
        terminal_writestring(", Error Code: ");
        terminal_write_hex(regs.err_code);
    }
    terminal_putchar('\n');

    if (regs.int_no == 33) { // Keyboard
        ubyte scancode = inb(0x60);
        if (!(scancode & 0x80)) {
            char c = scancode_to_char[scancode];
            if (c != 0) {
                terminal_putchar(c);
            }
        }
    } else if (regs.int_no < 32 && regs.int_no != 1 && regs.int_no != 3) { // CPU Exception
        if (regs.int_no == 13) { // GPF
            terminal_writestring("General Protection Fault! Selector: ");
            terminal_write_hex(regs.err_code);
            terminal_putchar('\n');
        } else if (regs.int_no == 14) { // Page Fault
            terminal_writestring("Page Fault! Details: ");
            terminal_write_hex(regs.err_code);
            uint fault_addr;
            asm { "mov %%cr2, %0" : "=r"(fault_addr); }
            terminal_writestring(" Addr: ");
            terminal_write_hex(fault_addr);
            terminal_putchar('\n');
        }
        if (regs.int_no != 2) {
            kernel_panic("CPU Exception Encountered.", cast(ErrorCode)regs.int_no);
        }
    }
}