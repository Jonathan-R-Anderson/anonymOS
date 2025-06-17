module kernel.pic;

// Assume these are provided by kernel.ports or similar and linked
extern (C) {
    ubyte inb(ushort port);
    void outb(ushort port, ubyte data);
}

enum PIC1_COMMAND_PORT = 0x20;
enum PIC1_DATA_PORT    = 0x21;
enum PIC2_COMMAND_PORT = 0xA0;
enum PIC2_DATA_PORT    = 0xA1;

enum PIC_EOI           = 0x20; // End-Of-Interrupt command code

// Initialization Control Word 1
enum ICW1_INIT         = 0x10; // Required for initialization
enum ICW1_ICW4         = 0x01; // Indicates ICW4 will be present

// Initialization Control Word 4
enum ICW4_8086         = 0x01; // 8086/88 (MCS-80/85) mode

// Remaps the PIC controllers.
// offset1: Vector offset for Master PIC (IRQs 0-7)
// offset2: Vector offset for Slave PIC (IRQs 8-15)
void pic_remap(ubyte offset1, ubyte offset2) {
    ubyte mask1, mask2;

    mask1 = inb(PIC1_DATA_PORT); // Save current masks
    mask2 = inb(PIC2_DATA_PORT);

    // Start initialization sequence (in cascade mode)
    outb(PIC1_COMMAND_PORT, ICW1_INIT | ICW1_ICW4);
    outb(PIC2_COMMAND_PORT, ICW1_INIT | ICW1_ICW4);

    outb(PIC1_DATA_PORT, offset1); // ICW2: Master PIC vector offset
    outb(PIC2_DATA_PORT, offset2); // ICW2: Slave PIC vector offset

    outb(PIC1_DATA_PORT, 4);       // ICW3: Tell Master PIC that there is a slave PIC at IRQ2 (00000100)
    outb(PIC2_DATA_PORT, 2);       // ICW3: Tell Slave PIC its cascade identity (00000010)

    outb(PIC1_DATA_PORT, ICW4_8086); // ICW4: Set 8086 mode
    outb(PIC2_DATA_PORT, ICW4_8086);

    outb(PIC1_DATA_PORT, mask1);   // Restore saved masks
    outb(PIC2_DATA_PORT, mask2);
}

void pic_send_eoi(ubyte irq) {
    if (irq >= 8) outb(PIC2_COMMAND_PORT, PIC_EOI); // If IRQ came from slave, send EOI to slave
    outb(PIC1_COMMAND_PORT, PIC_EOI);          // Always send EOI to master
}

void irq_clear_mask(ubyte irq_line) {
    ushort port = (irq_line < 8) ? PIC1_DATA_PORT : PIC2_DATA_PORT;
    ubyte irq_bit = (irq_line < 8) ? irq_line : cast(ubyte)(irq_line - 8);
    ubyte value = cast(ubyte)(inb(port) & ~(1 << irq_bit));
    outb(port, value);
}

void initialize_pic() {
    // Standard remapping: IRQs 0-7 to INT 0x20-0x27, IRQs 8-15 to INT 0x28-0x2F
    pic_remap(0x20, 0x28);
    // Initially, all IRQs are often masked after remapping.
    // Unmask them as handlers become available.
    // outb(PIC1_DATA_PORT, 0xFF); // Mask all on Master
    // outb(PIC2_DATA_PORT, 0xFF); // Mask all on Slave
}