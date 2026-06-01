module arch.x86_64.interrupts;

import core.io;
import core.utils;

extern (C):

@nogc nothrow:

import ldc.llvmasm;

struct idt_entry {
   align(1):
   ushort offset_1;
   ushort selector;
   ubyte ist;
   ubyte type_attr;
   ushort offset_2;
   uint offset_3;
   uint zero;
}

struct idt_ptr {
    align(1):
    ushort limit;
    ulong base;
}

static assert(idt_ptr.sizeof == 10);
static assert(idt_entry.sizeof == 16);

__gshared idt_entry[256] early_idt;
__gshared idt_ptr early_idt_ptr;

extern (C) ulong x64ReadCR2();

void early_fault_handler_d(ulong err_code, ulong rip, ulong vector) {
     klog("\n!!! EARLY BOOT EXCEPTION !!!\n");
     klog("Vector: "); klog_hex(vector); klog("\n");
     klog("RIP: "); klog_hex(rip); klog("\n");
     klog("Err: "); klog_hex(err_code); klog("\n");
// Read CR2
     ulong cr2 = x64ReadCR2();
     klog("CR2: "); klog_hex(cr2); klog("\n");
     while(1) { __asm("hlt", ""); }
}

extern void early_fault_asm();
extern (C) void loadIdt(idt_ptr*);

extern (C) {
    void isr0(); void isr1(); void isr2(); void isr3();
    void isr4(); void isr5(); void isr6(); void isr7();
    void isr8(); void isr9(); void isr10(); void isr11();
    void isr12(); void isr13(); void isr14(); void isr15();
    void isr16(); void isr17(); void isr18(); void isr19();
    void isr20(); void isr21(); void isr22(); void isr23();
    void isr24(); void isr25(); void isr26(); void isr27();
    void isr28(); void isr29(); void isr30(); void isr31();
}

void init_idt() {
     klog("init_idt: size of idt_ptr="); klog_hex(idt_ptr.sizeof); klog("\n");
     
     void*[32] stubs = [
         &isr0, &isr1, &isr2, &isr3, &isr4, &isr5, &isr6, &isr7,
         &isr8, &isr9, &isr10, &isr11, &isr12, &isr13, &isr14, &isr15,
         &isr16, &isr17, &isr18, &isr19, &isr20, &isr21, &isr22, &isr23,
         &isr24, &isr25, &isr26, &isr27, &isr28, &isr29, &isr30, &isr31
     ];

     for(int i=0; i<256; i++) {
         ulong handler;
         if (i < 32) handler = cast(ulong)stubs[i];
         else handler = cast(ulong)&early_fault_asm;

         early_idt[i].offset_1 = handler & 0xFFFF;
         early_idt[i].selector = 0x08; // Kernel Code
         early_idt[i].ist = 0;
         early_idt[i].type_attr = 0x8E;
         early_idt[i].offset_2 = (handler >> 16) & 0xFFFF;
         early_idt[i].offset_3 = (handler >> 32) & 0xFFFFFFFF;
         early_idt[i].zero = 0;
     }
     early_idt_ptr.limit = early_idt.sizeof - 1;
     early_idt_ptr.base = cast(ulong)early_idt.ptr;
      
     loadIdt(&early_idt_ptr);
}
