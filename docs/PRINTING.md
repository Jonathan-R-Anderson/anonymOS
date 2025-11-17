# Printing text during early boot

When running this OS under QEMU in legacy BIOS mode there are exactly two
reliable ways to put text on the screen. The option you choose depends on which
CPU mode you are currently in.

## 1. BIOS interrupt 0x10 (real mode only)

Before enabling protected mode you can rely on the firmware to render text via
the BIOS teletype service:

```asm
mov ah, 0x0E
mov al, 'H'
int 0x10
```

Once CR0.PE is set this option disappears unless you build a V8086 handler, so
our long-mode kernel cannot invoke it.

## 2. Direct VGA text mode writes (real → protected → long mode)

SeaBIOS leaves the machine in VGA text mode and the framebuffer always lives at
physical address `0xB8000`. Writing bytes directly into that buffer works in
real mode, early protected mode, and 64-bit long mode. The minimal D kernel
already uses this approach:

```d
extern(C) void printString(const(char)* msg)
{
    auto buf = cast(ushort*)0xB8000;
    size_t i = 0;
    while (msg[i])
    {
        buf[i] = cast(ushort)msg[i] | (0x0F << 8); // white on black
        ++i;
    }
}
```

This is the correct strategy once the boot code in `src/boot.s` enables
protected mode and jumps into `kmain`.

## Launching QEMU in BIOS mode

Using the wrong QEMU command line can silently switch you into UEFI mode, which
prevents the VGA memory mapping described above. Always boot with SeaBIOS:

```sh
qemu-system-x86_64 \
    -drive format=raw,file=os.img \
    -m 512M \
    -machine type=pc \
    -bios /usr/share/seabios/bios.bin
```

Do **not** pass `-bios OVMF.fd` or `-machine q35` when you need BIOS services.

## Optional serial logging

If you would rather see early boot logs in the terminal, enable the emulated
serial port:

```sh
qemu-system-x86_64 \
    -serial stdio \
    -drive format=raw,file=os.img
```

Then write bytes to the first serial port at I/O port `0x3F8`:

```asm
mov dx, 0x3F8
mov al, 'X'
out dx, al
```

This works in every CPU mode but requires you to initialise the UART yourself.
The kernel now performs this initialisation automatically inside `kmain()` and
mirrors every VGA character to COM1, so enabling `-serial stdio` will stream the
same log messages that appear on screen.
