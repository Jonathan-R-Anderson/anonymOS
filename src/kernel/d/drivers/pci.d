module drivers.pci;

import userland.shell.console : print, printHex, printLine, printUnsigned;
import core.io : inb, outb, klog, klog_hex, klog_dec;

@nogc nothrow:

private enum ushort pciConfigAddress = 0xCF8;
private enum ushort pciConfigData    = 0xCFC;

uint pciConfigRead32(ubyte bus, ubyte slot, ubyte func, ubyte offset)
{
    const uint address = (1u << 31) |
                         ((cast(uint)bus) << 16) |
                         ((cast(uint)slot) << 11) |
                         ((cast(uint)func) << 8) |
                         (offset & 0xFC);

    uint value;
    asm @nogc nothrow
    {
        mov DX, pciConfigAddress;
        mov EAX, address;
        out DX, EAX;
        mov DX, pciConfigData;
        in  EAX, DX;
        mov value, EAX;
    }

    return value;
}

void pciConfigWrite32(ubyte bus, ubyte slot, ubyte func, ubyte offset, uint value)
{
    const uint address = (1u << 31) |
                         ((cast(uint)bus) << 16) |
                         ((cast(uint)slot) << 11) |
                         ((cast(uint)func) << 8) |
                         (offset & 0xFC);

    asm @nogc nothrow
    {
        mov DX, pciConfigAddress;
        mov EAX, address;
        out DX, EAX;
        mov DX, pciConfigData;
        mov EAX, value;
        out DX, EAX;
    }
}

/// PCI Device structure
struct PCIDevice {
    ubyte bus;
    ubyte slot;
    ubyte func;
    ushort vendorId;
    ushort deviceId;
    ubyte classCode;
    ubyte subClass;
    ubyte progIf;
}

private __gshared PCIDevice[32] g_pciDevices;
private __gshared size_t g_pciDeviceCount = 0;

// ── WiFi / network-controller hardware survey (real-hardware bring-up) ─────────
// Walks PCI for network controllers (base class 0x02) and prints each device's
// vendor:device id, subclass (0x00=Ethernet, 0x80=Other/WiFi), BDF, and a decoded
// vendor + the Linux driver + firmware it will need — DIRECTLY to the framebuffer,
// so it is visible on a serial-less laptop during boot (before the desktop presents).
// This is what tells us which driver to compile into LKL and which firmware to fetch.
private void survFbHex(ulong v, int nibbles) @nogc nothrow {
    import core.console : console_framebuffer_write;
    static immutable char[16] hx = "0123456789abcdef";
    char[17] b;
    for (int i = nibbles - 1; i >= 0; --i) { b[i] = hx[v & 0xF]; v >>= 4; }
    b[nibbles] = 0;
    console_framebuffer_write(b.ptr);
}
// Vendor id → human name + the Linux WLAN driver (or wired driver) it maps to.
private const(char)* netVendorInfo(ushort vid, ubyte subClass) @nogc nothrow {
    const bool wifi = (subClass == 0x80);   // Network controller: Other == wireless (usually)
    switch (vid) {
        case 0x8086: return wifi ? "Intel  -> iwlwifi + iwlwifi firmware".ptr
                                 : "Intel  -> e1000e (wired)".ptr;
        case 0x10EC: return wifi ? "Realtek-> rtw88/rtw89 + rtw88 firmware".ptr
                                 : "Realtek-> r8169 (wired)".ptr;
        case 0x14C3: return "MediaTek -> mt76 + mt7921 firmware".ptr;
        case 0x14E4: return wifi ? "Broadcom -> brcmfmac + firmware".ptr
                                 : "Broadcom -> tg3 (wired)".ptr;
        case 0x168C: return "Qualcomm Atheros -> ath9k/ath10k + firmware".ptr;
        case 0x17CB: return "Qualcomm -> ath11k/ath12k + firmware".ptr;
        case 0x1AF4: return "virtio (VM)".ptr;
        default:     return "UNKNOWN vendor -> match modalias to a Linux driver".ptr;
    }
}

// Map a detected PCI device to the Linux driver `code` the installer offers (matching the DRIVERS[]
// codes in wl-installer.c where possible), or null if we don't surface it.  Drives the installer's
// auto-detect: /config/hardware.detect lists these codes and the Drivers page pre-checks the matches.
private const(char)* pciDriverCode(ref PCIDevice d) @nogc nothrow {
    if (d.classCode == 0x02) {                     // network controller
        const bool wifi = (d.subClass == 0x80);    // 0x00=Ethernet, 0x80=Other(wireless)
        switch (d.vendorId) {
            case 0x8086: return wifi ? "iwlwifi".ptr : "e1000e".ptr;
            case 0x10EC: return wifi ? "rtw88".ptr   : "r8169".ptr;
            case 0x14C3: return "mt76".ptr;
            case 0x14E4: return wifi ? "brcmfmac".ptr : "tg3".ptr;
            case 0x168C: return "ath9k".ptr;
            case 0x17CB: return "ath11k".ptr;
            case 0x1AF4: return "virtio_net".ptr;
            default:     return "net-unknown".ptr;
        }
    }
    if (d.classCode == 0x04) return "snd_hda_intel".ptr;   // multimedia/audio (PCI, not the USB mic path)
    return null;                                            // GPU/other: not an installable driver here
}

// Write a comma-separated list of driver codes for the PCI devices actually present into `buf` (NUL-
// terminated; returns byte length).  @nogc/fixed-buffer, mirrors wifiSurvey()'s use of scanPCIDevices().
// The USB peripherals (webcam/mic/kbd/mouse) live behind LKL and are merged in separately (milestone 3).
public size_t detectDriverCodes(char* buf, size_t cap) @nogc nothrow {
    size_t n = 0;
    if (cap == 0) return 0;
    auto devs = scanPCIDevices();
    foreach (ref d; devs) {
        auto code = pciDriverCode(d);
        if (code is null) continue;
        if (n > 0 && n + 1 < cap) buf[n++] = ',';
        while (*code != 0 && n + 1 < cap) buf[n++] = *code++;
    }
    buf[n] = 0;
    return n;
}
// The survey result is captured into these fixed lines so it can be RE-STAMPED onto the
// desktop every frame (the boot-log copy scrolls away when the compositor takes the
// screen).  Set g_wifiHudEnabled = false once the chip is known.
enum int WIFI_HUD_MAX = 4;
__gshared char[80][WIFI_HUD_MAX] g_wifiHud;
__gshared int  g_wifiHudN = 0;
__gshared bool g_wifiHudEnabled = true;

private void hudStr(ref char[80] b, ref int n, const(char)* s) @nogc nothrow {
    while (*s != 0 && n < 79) b[n++] = *s++;
}
private void hudHex(ref char[80] b, ref int n, uint v, int nib) @nogc nothrow {
    static immutable char[16] hx = "0123456789abcdef";
    for (int i = nib - 1; i >= 0 && n < 79; --i) b[n++] = hx[(v >> (i * 4)) & 0xF];
}

public void wifiSurvey() @nogc nothrow {
    import core.console : console_framebuffer_write;
    auto devs = scanPCIDevices();
    console_framebuffer_write("\n[wifi-survey] PCI network controllers (class 0x02):\n");
    g_wifiHudN = 0;
    foreach (ref d; devs) {
        if (d.classCode != 0x02) continue;
        // boot-log copy (serial + fb during boot)
        console_framebuffer_write("[wifi-survey] ");
        survFbHex(d.vendorId, 4); console_framebuffer_write(":"); survFbHex(d.deviceId, 4);
        console_framebuffer_write(d.subClass == 0x80 ? " WiFi  ".ptr : " wired ".ptr);
        console_framebuffer_write("bdf="); survFbHex(d.bus, 2); console_framebuffer_write(":");
        survFbHex(d.slot, 2); console_framebuffer_write("."); survFbHex(d.func, 1);
        console_framebuffer_write("  "); console_framebuffer_write(netVendorInfo(d.vendorId, d.subClass));
        console_framebuffer_write("\n");
        // persistent desktop-HUD copy
        if (g_wifiHudN < WIFI_HUD_MAX) {
            int n = 0; auto b = &g_wifiHud[g_wifiHudN];
            hudStr(*b, n, "WIFI ".ptr);
            hudHex(*b, n, d.vendorId, 4); hudStr(*b, n, ":".ptr); hudHex(*b, n, d.deviceId, 4);
            hudStr(*b, n, d.subClass == 0x80 ? " WiFi ".ptr : " wired ".ptr);
            hudStr(*b, n, "bdf="); hudHex(*b, n, d.bus, 2); hudStr(*b, n, ":".ptr);
            hudHex(*b, n, d.slot, 2); hudStr(*b, n, ".".ptr); hudHex(*b, n, d.func, 1);
            hudStr(*b, n, " ".ptr); hudStr(*b, n, netVendorInfo(d.vendorId, d.subClass));
            (*b)[n] = 0;
            g_wifiHudN++;
        }
    }
    if (g_wifiHudN == 0) {
        console_framebuffer_write("[wifi-survey] NO class-0x02 network controller found (WiFi may be USB/other bus)\n");
        int n = 0; hudStr(g_wifiHud[0], n, "WIFI: no class-0x02 controller (USB/other bus?)".ptr);
        g_wifiHud[0][n] = 0; g_wifiHudN = 1;
    }
}

// Re-stamp the captured survey onto the desktop.  Called after each compositor present
// (posix.d drmPresentFb) so it survives the desktop owning the framebuffer.  Lines start
// at pixel row 16 (below the mouse-packet HUD at row 0).
public void wifiSurveyRepaint() @nogc nothrow {
    import arch.x86_64.bootstrap : fb_draw_hud_row;
    if (!g_wifiHudEnabled) return;
    for (int i = 0; i < g_wifiHudN; i++)
        fb_draw_hud_row(cast(uint)(16 + i * 16), g_wifiHud[i].ptr);
}

/// Scan PCI bus and return list of devices
PCIDevice[] scanPCIDevices() {
    g_pciDeviceCount = 0;
    
    foreach (bus; 0 .. 256) {
        foreach (slot; 0 .. 32) {
            foreach (func; 0 .. 8) {
                const uint vendorDevice = pciConfigRead32(cast(ubyte)bus, cast(ubyte)slot, cast(ubyte)func, 0);
                if ((vendorDevice & 0xFFFF) == 0xFFFF) {
                    if (func == 0) break;
                    continue;
                }

                const ushort vendorId = cast(ushort)(vendorDevice & 0xFFFF);
                const ushort deviceId = cast(ushort)((vendorDevice >> 16) & 0xFFFF);
                const uint classRev = pciConfigRead32(cast(ubyte)bus, cast(ubyte)slot, cast(ubyte)func, 8);
                const ubyte baseClass = cast(ubyte)((classRev >> 24) & 0xFF);
                const ubyte subClass  = cast(ubyte)((classRev >> 16) & 0xFF);
                const ubyte progIf    = cast(ubyte)((classRev >> 8) & 0xFF);

                if (g_pciDeviceCount < g_pciDevices.length) {
                    g_pciDevices[g_pciDeviceCount] = PCIDevice(
                        cast(ubyte)bus, cast(ubyte)slot, cast(ubyte)func,
                        vendorId, deviceId, baseClass, subClass, progIf
                    );
                    g_pciDeviceCount++;
                }
            }
        }
    }
    
    return g_pciDevices[0 .. g_pciDeviceCount];
}

// ── PCIe ASPM disable — the AX210 RF/FSEQ "-110" fix ───────────────────────────
// Clears the ASPM Control field (bits 0-1 of each device's Link Control register in its PCI Express
// capability) — i.e. `pcie_aspm=off`, done by the real host.  WHY: the embedded LKL enumerates the
// AX210 as 0000:00:00.0 with NO parent bridge, so Linux's pci_disable_link_state() bails with -EINVAL
// (a root device has no upstream link_state) and iwlwifi CANNOT turn ASPM off itself.  ASPM L1 then
// stays as the BIOS left it, and the PCIe link entering L1 during the AX210's RF/FSEQ (CNVI companion
// chip) power-up corrupts the sequencer → FSEQ_ERROR_CODE=0x20000000 / "Failed to run INIT ucode: -110"
// — a CONSISTENT failure a cold boot cannot clear.  We (the actual host) own the links, so disable ASPM
// before the LKL loads firmware.  ASPM off costs a little idle power and never affects functionality.
// Logs to klog (Logs app filter "pci-aspm") so a real-HW boot shows exactly which links were changed.
public int pciDisableAspmAll() @nogc nothrow {
    int disabled = 0;
    auto devs = scanPCIDevices();
    foreach (ref d; devs) {
        // Capabilities List present?  Status register (0x06) bit 4 = bit 20 of the 0x04 dword.
        const uint statusCmd = pciConfigRead32(d.bus, d.slot, d.func, 0x04);
        if (!((statusCmd >> 16) & 0x10)) continue;
        // Walk the capability linked list from the cap pointer (byte at 0x34).
        ubyte cap = cast(ubyte)(pciConfigRead32(d.bus, d.slot, d.func, 0x34) & 0xFC);
        int guard = 0;
        while (cap >= 0x40 && guard++ < 48) {
            const uint hdr   = pciConfigRead32(d.bus, d.slot, d.func, cap);
            const ubyte id   = cast(ubyte)(hdr & 0xFF);
            const ubyte next = cast(ubyte)((hdr >> 8) & 0xFC);
            if (id == 0x10) {                                       // PCI Express capability
                const ubyte lnk = cast(ubyte)(cap + 0x10);         // Link Control (low16) / Status (high16)
                const uint dw = pciConfigRead32(d.bus, d.slot, d.func, lnk);
                if (dw & 0x3) {                                     // ASPM Control (L0s|L1) enabled → off
                    // Keep Link Control bits 2..15, clear ASPM bits 0-1; write 0 to Link Status (its
                    // RW1C bits are no-ops on a 0 write, so we don't disturb them).
                    pciConfigWrite32(d.bus, d.slot, d.func, lnk, dw & 0x0000FFFCu);
                    ++disabled;
                    klog("[pci-aspm] off bdf=0x");
                    klog_hex((cast(ulong)d.bus << 16) | (cast(ulong)d.slot << 8) | d.func);
                    klog(" vid=0x"); klog_hex(d.vendorId); klog(" did=0x"); klog_hex(d.deviceId);
                    klog(" lnkctl 0x"); klog_hex(dw & 0xFFFF);
                    klog("->0x"); klog_hex(dw & 0xFFFC); klog("\n");
                }
                break;
            }
            cap = next;
        }
    }
    klog("[pci-aspm] ASPM cleared on "); klog_dec(disabled); klog(" PCIe link(s)\n");
    return disabled;
}

/// Basic bus walk that logs every present device/function with IDs and class.
void initializePCI()
{
    printLine("[pci] Enumerating devices");
    
    auto devices = scanPCIDevices();
    
    foreach (dev; devices) {
        print("[pci] ");
        printHex(dev.bus); print(":"); printHex(dev.slot); print("."); printHex(dev.func);
        print(" vid:"); printHex(dev.vendorId);
        print(" did:"); printHex(dev.deviceId);
        print(" class:"); printHex(dev.classCode);
        print("."); printHex(dev.subClass);
        print("."); printHex(dev.progIf);
        printLine("");
    }

    printLine("[pci] enumeration complete");
}

// ─── Boot-time INPUT HARDWARE SURVEY (debug) ────────────────────────────────
// On this laptop there is no serial and no USB input, and the compositor wipes
// the on-screen boot log when it grabs the framebuffer.  This dumps every PCI
// device (annotating the buses that could carry input) plus an i8042/PS-2 probe,
// then HALTS on a readable screen so the hardware can be photographed.  The
// result tells us which path can actually drive the trackpad/keyboard:
//   * USB xHCI (class 0c.03)         -> LKL USB-HID path already works
//   * Intel LPSS I2C (class 0c.80)   -> trackpad is I2C-HID (needs ACPI/GPIO; LKL can't today)
//   * i8042 self-test 0x55           -> a native PS/2 driver is viable
// Remove the call in d_kernel_main once the hardware is identified.
private void survAnno(ubyte cls, ubyte sub, ubyte progif)
{
    if (cls == 0x0C && sub == 0x03)      print("   <- USB controller (USB-HID input via LKL)");
    else if (cls == 0x0C && sub == 0x05) print("   <- SMBus");
    else if (cls == 0x0C && sub == 0x80) print("   <- other serial bus (maybe Intel LPSS I2C = trackpad)");
    else if (cls == 0x11)                print("   <- signal-processing (maybe Intel LPSS = I2C/trackpad)");
    else if (cls == 0x03)                print("   <- display controller (GPU)");
    else if (cls == 0x01 && sub == 0x08) print("   <- NVMe storage");
    else if (cls == 0x01)                print("   <- storage controller");
    else if (cls == 0x02)                print("   <- network controller");
}

private bool survWaitInputClear()
{
    int g = 200000;
    while ((inb(0x64) & 0x02) && g-- > 0) {}
    return g > 0;
}

private void survProbeI8042()
{
    printLine("");
    printLine("[i8042] probing legacy PS/2 controller (ports 0x60/0x64)...");

    ubyte st = inb(0x64);
    print("[i8042] status port 0x64 = "); printHex(st); printLine("");
    if (st == 0xFF) {
        printLine("[i8042] status floats 0xFF -> NO 8042 controller present");
        return;
    }

    // Drain any pending output, then disable both ports for a clean self-test.
    int guard = 2000;
    while ((inb(0x64) & 0x01) && guard-- > 0) { inb(0x60); }
    if (survWaitInputClear()) outb(0x64, 0xAD);   // disable port 1
    if (survWaitInputClear()) outb(0x64, 0xA7);   // disable port 2
    guard = 2000;
    while ((inb(0x64) & 0x01) && guard-- > 0) { inb(0x60); }

    // Controller self-test: 0xAA -> expect 0x55.
    if (!survWaitInputClear()) { printLine("[i8042] input buffer stuck busy -> controller not usable"); return; }
    outb(0x64, 0xAA);
    guard = 400000;
    while (!(inb(0x64) & 0x01) && guard-- > 0) {}
    if (guard <= 0) { printLine("[i8042] self-test TIMEOUT (no response) -> controller absent/dead"); return; }
    ubyte resp = inb(0x60);
    print("[i8042] self-test response = "); printHex(resp);
    if (resp == 0x55) printLine("  -> PASS: an 8042 IS present (native PS/2 driver viable)");
    else              printLine("  -> unexpected (not 0x55)");

    // Second-port (mouse/trackpad) test: 0xA9 -> 0x00 means the aux port exists.
    if (survWaitInputClear()) {
        outb(0x64, 0xA9);
        guard = 400000;
        while (!(inb(0x64) & 0x01) && guard-- > 0) {}
        if (guard > 0) {
            ubyte mr = inb(0x60);
            print("[i8042] aux(mouse) port test = "); printHex(mr);
            printLine(mr == 0x00 ? "  -> aux port present (trackpad may be PS/2)" : "  -> aux port test non-zero");
        } else {
            printLine("[i8042] aux port test TIMEOUT (no second port?)");
        }
    }
}

public void inputHardwareSurvey()
{
    printLine("");
    printLine("================ INPUT HARDWARE SURVEY (photograph this) ================");
    auto devices = scanPCIDevices();
    foreach (dev; devices) {
        print("[pci] ");
        printHex(dev.bus); print(":"); printHex(dev.slot); print("."); printHex(dev.func);
        print(" vid:"); printHex(dev.vendorId);
        print(" did:"); printHex(dev.deviceId);
        print(" class:"); printHex(dev.classCode);
        print("."); printHex(dev.subClass);
        print("."); printHex(dev.progIf);
        survAnno(dev.classCode, dev.subClass, dev.progIf);
        printLine("");
    }
    survProbeI8042();
    printLine("");
    printLine("=== survey complete; system HALTED. Photograph the screen and send it. ===");
    for (;;) { asm @nogc nothrow { cli; hlt; } }
}
