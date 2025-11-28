module anonymos.drivers.usb_hid;

import core.volatile : volatileLoad;
import anonymos.console : print, printLine, printHex, printUnsigned;
import anonymos.display.input_pipeline : InputQueue, enqueue, InputEvent;
import anonymos.display.framebuffer : g_fb;
import anonymos.drivers.hid_keyboard : HIDKeyboardReport, processKeyboardReport;
import anonymos.drivers.hid_mouse : HIDMouseReport, processMouseReport;
import anonymos.kernel.dma : dma_alloc;

@nogc:
nothrow:

/// USB HID device types we support
enum HIDDeviceType : ubyte
{
    none = 0,
    keyboard = 1,
    mouse = 2,
}

/// USB controller types
enum USBControllerType : ubyte
{
    none = 0,
    uhci = 1,  // USB 1.1
    ehci = 2,  // USB 2.0
    xhci = 3,  // USB 3.0+
}

/// Represents a detected USB HID device
struct HIDDevice
{
    HIDDeviceType deviceType;
    bool enabled;
    ubyte address;
    ubyte endpoint;
    ushort vendorId;
    ushort productId;
}

/// USB HID subsystem state
struct USBHIDSubsystem
{
    @nogc nothrow:

    USBControllerType controllerType;
    uint controllerBus;
    uint controllerSlot;
    uint controllerFunction;
    ulong controllerMmioBase;   // FIX: allow 64-bit BARs
    bool initialized;
    bool usbHostActive;
    HIDDevice[8] devices;
    ubyte deviceCount;
    bool pointerPresent;
    bool touchPresent;
    bool keyboardPresent;

    void initialize()
    {
        if (initialized)
        {
            return;
        }

        printLine("[usb-hid] Initializing USB HID subsystem...");

        pointerPresent = false;
        touchPresent = false;
        keyboardPresent = false;
        controllerMmioBase = 0;
        usbHostActive = false;

        // Always bring up legacy PS/2 first; this is our fallback path.
        // If QEMU/firmware routes HID through i8042 legacy, we’ll see it here.
        initializeLegacyPS2();

        // Detect USB controllers
        controllerType = detectUSBController(controllerBus,
                                             controllerSlot,
                                             controllerFunction,
                                             controllerMmioBase);

        if (controllerType == USBControllerType.none)
        {
            printLine("[usb-hid] No USB controllers detected; legacy PS/2 only");
            initialized = true;
            return;
        }

        print("[usb-hid] Found controller: ");
        printLine(controllerTypeName(controllerType));

        // NOTE:
        // Previously this code *skipped* xHCI init and then lied by setting
        // pointerPresent/keyboardPresent true and initialized=true. That made
        // higher layers believe USB was online even though the host stack was off,
        // causing "desktop loads but never sees input" on modern QEMU (xhci default).
        //
        // We now:
        //  1) do NOT fake device presence,
        //  2) attempt xHCI init if detected,
        //  3) if xHCI init fails, cleanly fall back to PS/2 without claiming USB works.

        // Initialize the controller
        if (!initializeController())
        {
            printLine("[usb-hid] Failed to initialize USB controller; falling back to PS/2 only");
            usbHostActive = false;
            initialized = true;
            return;
        }

        usbHostActive = true;

        // Enumerate HID devices (only xHCI path exists today)
        enumerateHIDDevices();

        print("[usb-hid] Detected ");
        printUnsigned(deviceCount);
        printLine(" HID device(s)");

        initialized = true;
    }

    void poll(ref InputQueue queue)
    {
        // Always service legacy PS/2/USB-legacy routing if present.
        pollLegacyPS2(queue);

        if (!initialized || !usbHostActive)
        {
            return;
        }

        // Poll each enabled HID device
        foreach (ref device; devices[0 .. deviceCount])
        {
            if (!device.enabled)
            {
                continue;
            }

            pollDevice(device, queue);
        }

        // Process any pending xHCI events (command completions, port changes)
        if (controllerType == USBControllerType.xhci)
        {
            handleEvents(queue);
        }
    }

    private bool initializeController()
    {
        final switch (controllerType)
        {
            case USBControllerType.uhci:
                return initializeUHCI(controllerBus, controllerSlot, controllerFunction);
            case USBControllerType.ehci:
                return initializeEHCI(controllerBus, controllerSlot, controllerFunction,
                                      cast(uint)controllerMmioBase);
            case USBControllerType.xhci:
                if (!initializeXHCI(controllerBus, controllerSlot, controllerFunction,
                                    cast(uint)controllerMmioBase))
                    return false;

                // xHCI won't enumerate anything if ports aren't powered.
                powerOnXHCIPorts();
                return true;
            case USBControllerType.none:
                return false;
        }
    }

    private void enumerateHIDDevices()
    {
        deviceCount = 0;
        keyboardPresent = false;
        pointerPresent = false;
        touchPresent = false;

        final switch (controllerType)
        {
            case USBControllerType.xhci:
                enumerateXHCIDevices();
                break;
            case USBControllerType.ehci:
            case USBControllerType.uhci:
            case USBControllerType.none:
                // TODO: add UHCI/EHCI enumeration once host controller drivers exist
                break;
        }
    }

    private void pollDevice(ref HIDDevice device, ref InputQueue queue)
    {
        // Poll the USB endpoint for new HID reports
        final switch (device.deviceType)
        {
            case HIDDeviceType.keyboard:
                pollKeyboard(device, queue);
                break;
            case HIDDeviceType.mouse:
                pollMouse(device, queue);
                break;
            case HIDDeviceType.none:
                break;
        }
    }

    private void powerOnXHCIPorts()
    {
        if (controllerMmioBase == 0)
        {
            return;
        }

        const ubyte capLength = volatileLoad(cast(ubyte*)(cast(uint)controllerMmioBase));
        const uint hcsParams1 = mmioRead32(cast(uint)controllerMmioBase, 0x04);
        const uint portCount = (hcsParams1 >> 24) & 0xFF;
        const uint portBase = cast(uint)controllerMmioBase + capLength + 0x400; // port register set base

        foreach (portIndex; 0 .. portCount)
        {
            const uint portOffset = portIndex * 0x10;
            uint portStatus = mmioRead32(portBase, portOffset);
            // Set Port Power (PP, bit 9) and clear Port Reset (PR, bit 4).
            portStatus |= (1u << 9);
            portStatus &= ~(1u << 4);
            mmioWrite32(portBase, portOffset, portStatus);
        }
    }

    private void pollKeyboard(ref HIDDevice device, ref InputQueue queue)
    {
        // TODO: submit transfer descriptors and parse real HID keyboard reports
        // when a complete USB host stack is available.
    }

    private void pollMouse(ref HIDDevice device, ref InputQueue queue)
    {
        // Real USB transfers are not wired yet; input is collected via the
        // legacy PS/2 compatibility path in poll(), which also services USB
        // legacy routing provided by firmware/QEMU.
    }

    private void enumerateXHCIDevices()
    {
        if (controllerMmioBase == 0)
        {
            printLine("[usb-hid] No MMIO base for XHCI; skipping enumeration");
            return;
        }

        // Ensure we have at least one slot/EP0 configured.
        if (g_xhci.lastSlotId == 0)
        {
            uint slotId;
            if (!submitEnableSlot(slotId))
            {
                printLine("[usb-hid] Enable Slot failed; cannot enumerate");
                return;
            }
            g_xhci.lastSlotId = slotId;
            if (!setupEndpointContexts(slotId))
            {
                printLine("[usb-hid] Endpoint context setup failed");
                return;
            }
        }

        // Fetch device and configuration descriptors and derive HID endpoint info.
        USBDeviceDescriptor devDesc;
        if (!fetchDeviceDescriptor(g_xhci.lastSlotId, devDesc))
        {
            printLine("[usb-hid] Failed to read device descriptor");
            return;
        }

        ubyte* cfgBuf;
        uint cfgLen;
        HIDEndpointInfo hidInfo;
        if (!fetchConfigurationDescriptor(g_xhci.lastSlotId, 0, cfgBuf, cfgLen) ||
            !parseHidFromConfig(cfgBuf, cfgLen, hidInfo))
        {
            printLine("[usb-hid] No HID interface found in configuration");
            return;
        }

        if (deviceCount < devices.length)
        {
            auto device = &devices[deviceCount++];
            device.deviceType = hidInfo.devType;
            device.enabled = true;
            device.address = cast(ubyte)g_xhci.lastSlotId;
            device.endpoint = hidInfo.endpoint;
            device.vendorId = devDesc.idVendor;
            device.productId = devDesc.idProduct;

            if (hidInfo.devType == HIDDeviceType.keyboard)
            {
                keyboardPresent = true;
            }
            else if (hidInfo.devType == HIDDeviceType.mouse)
            {
                pointerPresent = true;
            }
        }
    }
}


// --------------------------------------------------------------------------
// xHCI helpers: rings and controller init
// --------------------------------------------------------------------------

private bool allocateTrbRing(uint trbCount, out XHCIRing ring) @nogc nothrow
{
    ring = XHCIRing.init;
    const size_t bytes = cast(size_t)trbCount * TRB.sizeof;
    ulong phys;
    auto virt = cast(TRB*)dma_alloc(bytes, 64, &phys);
    if (virt is null)
    {
        return false;
    }

    ring.trbs = virt;
    ring.phys = phys;
    ring.size = trbCount;
    ring.enqueueIndex = 0;
    ring.cycle = 1; // start cycle state at 1

    // Link TRB at end to form a ring; toggle cycle on wrap.
    auto link = &ring.trbs[trbCount - 1];
    link.d[0] = cast(uint)(ring.phys & 0xFFFF_FFF0);
    link.d[1] = cast(uint)(ring.phys >> 32);
    link.d[2] = 0;
    const uint linkType = 6; // Link TRB
    const uint toggleCycle = 1 << 1;
    link.d[3] = (ring.cycle & 0x1) | toggleCycle | (linkType << 10);

    return true;
}

private uint maxScratchpads(uint hcsParams2) @nogc nothrow pure
{
    const uint lo = (hcsParams2 >> 21) & 0x1F;
    const uint hi = (hcsParams2 >> 27) & 0x1F;
    return lo | (hi << 5);
}

private bool setupScratchpads(uint count, ref ulong dcbaa0Out) @nogc nothrow
{
    if (count == 0)
    {
        dcbaa0Out = 0;
        return true;
    }

    ulong scratchArrayPhys;
    auto scratchArray = cast(ulong*)dma_alloc(count * ulong.sizeof, 64, &scratchArrayPhys);
    if (scratchArray is null)
    {
        return false;
    }

    foreach (i; 0 .. count)
    {
        ulong bufPhys;
        auto buf = dma_alloc(4096, 4096, &bufPhys);
        if (buf is null)
        {
            return false;
        }
        scratchArray[i] = bufPhys;
    }

    dcbaa0Out = scratchArrayPhys;
    return true;
}

private void programEventRing(uint interrupterBase, ref XHCIEventRing er) @nogc nothrow
{
    // ERSTSZ
    mmioWrite32(interrupterBase, 0x08, 1);
    // ERSTBA
    mmioWrite32(interrupterBase, 0x10, cast(uint)(er.erstPhys & 0xFFFF_FFFF));
    mmioWrite32(interrupterBase, 0x14, cast(uint)(er.erstPhys >> 32));
    // ERDP
    mmioWrite32(interrupterBase, 0x18, cast(uint)(er.ring.phys & 0xFFFF_FFFF));
    mmioWrite32(interrupterBase, 0x1C, cast(uint)(er.ring.phys >> 32));
    // IMAN: enable interrupts (bit 1)
    const uint iman = (1u << 1);
    mmioWrite32(interrupterBase, 0x00, iman);
}

private void updateEventRingDequeue(ref XHCIEventRing er, uint interrupterBase) @nogc nothrow
{
    const ulong deqPhys = er.ring.phys + cast(ulong)(er.dequeueIndex * TRB.sizeof);
    mmioWrite32(interrupterBase, 0x18, cast(uint)(deqPhys & 0xFFFF_FFFF));
    mmioWrite32(interrupterBase, 0x1C, cast(uint)(deqPhys >> 32));
}

private bool initializeXHCIRings(uint mmioBase) @nogc nothrow
{
    g_xhci.mmioBase = mmioBase;

    const ubyte capLength = volatileLoad(cast(ubyte*)(mmioBase));
    const uint hcsParams1 = mmioRead32(mmioBase, 0x04);
    const uint hcsParams2 = mmioRead32(mmioBase, 0x08);
    const uint hccParams1 = mmioRead32(mmioBase, 0x10);
    const uint doorbellOffset = mmioRead32(mmioBase, 0x14);
    const uint runtimeOffset = mmioRead32(mmioBase, 0x18);

    g_xhci.opBase = mmioBase + capLength;
    g_xhci.runtimeBase = mmioBase + (runtimeOffset & 0xFFFF_FFE0);
    g_xhci.doorbellBase = mmioBase + (doorbellOffset & 0xFFFF_FFFC);
    g_xhci.hcsParams1 = hcsParams1;
    g_xhci.hcsParams2 = hcsParams2;
    g_xhci.maxSlots = hcsParams1 & 0xFF;

    // Stop the controller
    mmioWrite32(g_xhci.opBase, 0x00, mmioRead32(g_xhci.opBase, 0x00) & ~1u);
    foreach (_; 0 .. 100_000)
    {
        const uint usbsts = mmioRead32(g_xhci.opBase, 0x04);
        const bool halted = (usbsts & 0x01) != 0;
        const bool cnr = (usbsts & (1 << 11)) != 0;
        if (halted && !cnr)
        {
            break;
        }
    }

    // Reset controller
    mmioWrite32(g_xhci.opBase, 0x00, mmioRead32(g_xhci.opBase, 0x00) | (1u << 1));
    foreach (_; 0 .. 100_000)
    {
        const uint usbsts = mmioRead32(g_xhci.opBase, 0x04);
        const bool resetting = (mmioRead32(g_xhci.opBase, 0x00) & (1u << 1)) != 0;
        const bool cnr = (usbsts & (1 << 11)) != 0;
        if (!resetting && !cnr)
        {
            break;
        }
    }

    // Program page size: enable 4KiB
    mmioWrite32(g_xhci.opBase, 0x08, 0x0001);

    // DCBAA
    const size_t dcbaaEntries = g_xhci.maxSlots + 1;
    ulong dcbaaPhys;
    auto dcbaa = cast(ulong*)dma_alloc(dcbaaEntries * ulong.sizeof, 64, &dcbaaPhys);
    if (dcbaa is null)
    {
        printLine("[usb-hid] xHCI DCBAA allocation failed");
        return false;
    }
    g_xhci.dcbaa = dcbaa;
    g_xhci.dcbaaPhys = dcbaaPhys;

    const uint scratchCount = maxScratchpads(hcsParams2);
    ulong dcbaa0 = 0;
    if (!setupScratchpads(scratchCount, dcbaa0))
    {
        printLine("[usb-hid] xHCI scratchpad allocation failed");
        return false;
    }
    g_xhci.dcbaa[0] = dcbaa0;
    g_xhci.scratchArrayPhys = dcbaa0;

    mmioWrite32(g_xhci.opBase, 0x30, cast(uint)(dcbaaPhys & 0xFFFF_FFFF));
    mmioWrite32(g_xhci.opBase, 0x34, cast(uint)(dcbaaPhys >> 32));

    // Command ring
    if (!allocateTrbRing(256, g_xhci.commandRing))
    {
        printLine("[usb-hid] xHCI command ring allocation failed");
        return false;
    }

    const uint crcrLow = cast(uint)((g_xhci.commandRing.phys & 0xFFFF_FFC0) | (g_xhci.commandRing.cycle & 0x1));
    const uint crcrHigh = cast(uint)(g_xhci.commandRing.phys >> 32);
    mmioWrite32(g_xhci.opBase, 0x18, crcrLow);
    mmioWrite32(g_xhci.opBase, 0x1C, crcrHigh);

    // Event ring
    if (!allocateTrbRing(256, g_xhci.eventRing.ring))
    {
        printLine("[usb-hid] xHCI event ring allocation failed");
        return false;
    }
    g_xhci.eventRing.dequeueIndex = 0;
    g_xhci.eventRing.cycle = 1;

    ulong erstPhys;
    auto erst = cast(ERSTEntry*)dma_alloc(ERSTEntry.sizeof, 64, &erstPhys);
    if (erst is null)
    {
        printLine("[usb-hid] xHCI ERST allocation failed");
        return false;
    }
    erst[0].ringBase = g_xhci.eventRing.ring.phys;
    erst[0].ringSize = g_xhci.eventRing.ring.size;
    erst[0].reserved = 0;
    g_xhci.eventRing.erst = erst;
    g_xhci.eventRing.erstPhys = erstPhys;

    const uint interrupterBase = g_xhci.runtimeBase + 0x20 * 0;
    programEventRing(interrupterBase, g_xhci.eventRing);
    g_xhci.eventRing.dequeueIndex = 0;
    g_xhci.eventRing.cycle = 1;

    // Enable slots
    mmioWrite32(g_xhci.opBase, 0x38, g_xhci.maxSlots & 0xFF);

    // Run controller, enable interrupts
    uint usbcmd = mmioRead32(g_xhci.opBase, 0x00);
    usbcmd |= (1u << 2); // INTE
    usbcmd |= 0x01;      // RS
    mmioWrite32(g_xhci.opBase, 0x00, usbcmd);

    // Wait until not halted
    foreach (_; 0 .. 100_000)
    {
        const uint usbsts = mmioRead32(g_xhci.opBase, 0x04);
        if ((usbsts & 0x01) == 0)
        {
            break;
        }
    }

    printLine("[usb-hid] xHCI rings initialised");

    // Enable a default slot and set up EP0 ring/contexts to permit control transfers.
    uint slotId;
    if (submitEnableSlot(slotId))
    {
        g_xhci.lastSlotId = slotId;
        if (!setupEndpointContexts(slotId))
        {
            printLine("[usb-hid] Endpoint context setup failed");
        }
        else
        {
            // Kick a GET_DESCRIPTOR on EP0 to sanity check transfers
            submitControlTransferGetDescriptor(slotId);
        }
    }
    else
    {
        printLine("[usb-hid] Enable Slot failed");
    }

    return true;
}


// --------------------------------------------------------------------------
// Legacy PS/2 compatibility path (covers USB legacy routing in QEMU/firmware)
// --------------------------------------------------------------------------

private enum ushort ps2DataPort   = 0x60;
private enum ushort ps2StatusPort = 0x64;
private enum ubyte  ps2StatusOutputFull = 0x01;
private enum ubyte  ps2StatusInputFull  = 0x02;
private enum ubyte  ps2StatusIsMouse    = 0x20;
private enum size_t ps2IsrQueueSize = 64;

private __gshared bool g_ps2Initialized = false;
private __gshared bool g_ps2Extended = false;
private __gshared HIDKeyboardReport g_ps2KeyboardReport;
private __gshared ubyte[3] g_ps2MousePacket;
private __gshared ubyte g_ps2MouseIndex = 0;
private __gshared ubyte[ps2IsrQueueSize] g_ps2IsrStatus;
private __gshared ubyte[ps2IsrQueueSize] g_ps2IsrData;
private __gshared size_t g_ps2IsrHead = 0;
private __gshared size_t g_ps2IsrTail = 0;
private __gshared bool g_ps2PollingMouse = false; // rely on IRQ stream by default to avoid duplicate packets

private ubyte inb(ushort port) @nogc nothrow
{
    ubyte value;
    asm @nogc nothrow
    {
        mov DX, port;
        in  AL, DX;
        mov value, AL;
    }
    return value;
}

private void outb(ushort port, ubyte value) @nogc nothrow
{
    asm @nogc nothrow
    {
        mov DX, port;
        mov AL, value;
        out DX, AL;
    }
}

private bool ps2WaitInputClear() @nogc nothrow
{
    foreach (_; 0 .. 100_000)
    {
        if ((inb(ps2StatusPort) & ps2StatusInputFull) == 0)
        {
            return true;
        }
        ioWait();
    }
    printLine("[usb-hid] PS/2 input buffer never cleared");
    return false;
}

// Small I/O delay so PS/2 controller has time to react.
// Reading/writing port 0x80 is the classic POST delay.
private void ioWait() @nogc nothrow
{
    asm @nogc nothrow
    {
        xor AL, AL;
        mov DX, 0x80;
        out DX, AL;
    }
}

private bool ps2WaitOutputFull() @nogc nothrow
{
    foreach (_; 0 .. 100_000)
    {
        if ((inb(ps2StatusPort) & ps2StatusOutputFull) != 0)
        {
            return true;
        }
        ioWait();
    }
    printLine("[usb-hid] PS/2 output buffer never filled");
    return false;
}

private void ps2WriteCommand(ubyte cmd) @nogc nothrow
{
    if (!ps2WaitInputClear())
    {
        printLine("[usb-hid] PS/2 command wait timeout");
        return;
    }
    outb(ps2StatusPort, cmd);
}

private void ps2WriteData(ubyte data) @nogc nothrow
{
    if (!ps2WaitInputClear())
    {
        printLine("[usb-hid] PS/2 data wait timeout");
        return;
    }
    outb(ps2DataPort, data);
}

private ubyte ps2ReadData() @nogc nothrow
{
    if (!ps2WaitOutputFull()) return 0;
    return inb(ps2DataPort);
}

private ubyte ps2SendMouseCommand(ubyte cmd) @nogc nothrow
{
    // Route next byte to mouse
    ps2WriteCommand(0xD4);
    ps2WriteData(cmd);
    if (!ps2WaitOutputFull()) return 0;
    return inb(ps2DataPort); // ACK or error
}

private bool initializeLegacyPS2() @nogc nothrow
{
    static bool warned;

    auto fail = () @nogc nothrow {
        if (!warned)
        {
            printLine("[usb-hid] PS/2 init failed; no legacy input available");
            warned = true;
        }
        return false;
    };

    if (g_ps2Initialized)
    {
        return true;
    }

    // Mask keyboard/mouse IRQs during init to prevent ACKs being consumed by ISRs.
    const ubyte origPic1Mask = inb(0x21);
    const ubyte origPic2Mask = inb(0xA1);
    outb(0x21, origPic1Mask | 0x02); // mask IRQ1
    outb(0xA1, 0xFF);                // mask all on slave

    // 1. Disable devices
    ps2WriteCommand(0xAD); // Disable Keyboard
    ps2WriteCommand(0xA7); // Disable Mouse

    // 2. Flush buffer
    while ((inb(ps2StatusPort) & ps2StatusOutputFull) != 0)
    {
        ps2ReadData();
    }

    // 3. Setup Config Byte
    ps2WriteCommand(0x20); // Read Config
    if (!ps2WaitOutputFull()) return fail();
    ubyte config = inb(ps2DataPort); // already waited

    config |= 0x40;           // Translation on (bit 6)
    config &= ~(0x10 | 0x20); // Clear "clock disable" bits 4/5 to enable kbd/mouse
    config |= 0x03;           // Enable IRQ1/IRQ12
    ps2WriteCommand(0x60);    // Write Config
    ps2WriteData(config);

    // 4. Enable Devices
    ps2WriteCommand(0xAE); // Enable Keyboard
    ps2WriteCommand(0xA8); // Enable Mouse

    // 5. Initialize Mouse: defaults, stream mode, enable reporting
    ps2WriteCommand(0xD4);
    ps2WriteData(0xF6);
    if (ps2WaitOutputFull()) cast(void)inb(ps2DataPort); // ACK

    ps2WriteCommand(0xD4);
    ps2WriteData(0xEA); // stream mode
    if (ps2WaitOutputFull()) cast(void)inb(ps2DataPort); // ACK

    ps2WriteCommand(0xD4);
    ps2WriteData(0xF4); // enable data reporting
    if (ps2WaitOutputFull())
    {
        ps2ReadData(); // ACK
        printLine("[usb-hid] PS/2 mouse enabled successfully");
    }
    else
    {
        printLine("[usb-hid] PS/2 mouse enable timed out");
    }

    // Enable keyboard scanning (0xF4).
    ps2WriteData(0xF4);
    if (ps2WaitOutputFull())
    {
        ps2ReadData(); // ACK
        printLine("[usb-hid] PS/2 keyboard enabled successfully");
    }
    else
    {
        printLine("[usb-hid] PS/2 keyboard enable timed out");
    }

    g_ps2Initialized = true;
    printLine("[usb-hid] PS/2 legacy input enabled");

    // Restore PIC masks to defaults (unmask timer/kbd/mouse).
    import anonymos.kernel.interrupts : PIC1_DEFAULT_MASK, PIC2_DEFAULT_MASK;
    outb(0xA1, PIC2_DEFAULT_MASK);
    outb(0x21, PIC1_DEFAULT_MASK);
    return true;
}

extern(C) @nogc nothrow void ps2IsrEnqueue(ubyte status, ubyte data)
{
    const size_t next = (g_ps2IsrTail + 1) % ps2IsrQueueSize;
    if (next == g_ps2IsrHead)
    {
        return; // drop if buffer full
    }
    g_ps2IsrStatus[g_ps2IsrTail] = status;
    g_ps2IsrData[g_ps2IsrTail] = data;
    g_ps2IsrTail = next;
}

private ubyte mapSet1ToHid(ubyte code, bool extended) @nogc nothrow pure
{
    immutable ubyte[0x59] table = [
        0, 0x29, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23,
        0x24, 0x25, 0x26, 0x27, 0x2D, 0x2E, 0x2A, 0x2B,
        0x14, 0x1A, 0x08, 0x15, 0x17, 0x1C, 0x18, 0x0C,
        0x12, 0x13, 0x2F, 0x30, 0x28, 0xE0, 0x04, 0x16,
        0x07, 0x09, 0x0A, 0x0B, 0x0D, 0x0E, 0x0F, 0x33,
        0x34, 0x35, 0xE1, 0x31, 0x1D, 0x1B, 0x06, 0x19,
        0x05, 0x11, 0x10, 0x36, 0x37, 0x38, 0xE5, 0x55,
        0xE2, 0x2C, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E,
        0x3F, 0x40, 0x41, 0x42, 0x43, 0x53, 0x47, 0x5F,
        0x60, 0x61, 0x56, 0x5C, 0x5D, 0x5E, 0x57, 0x59,
        0x5A, 0x5B, 0x62, 0x63, 0, 0, 0, 0x44, 0x45
    ];

    if (extended)
    {
        switch (code)
        {
            case 0x1C: return 0x58; // KP Enter
            case 0x1D: return 0xE4; // Right Ctrl
            case 0x35: return 0x54; // KP /
            case 0x38: return 0xE6; // Right Alt
            case 0x47: return 0x4A; // Home
            case 0x48: return 0x52; // Up
            case 0x49: return 0x4B; // Page Up
            case 0x4B: return 0x50; // Left
            case 0x4D: return 0x4F; // Right
            case 0x4F: return 0x4D; // End
            case 0x50: return 0x51; // Down
            case 0x51: return 0x4E; // Page Down
            case 0x52: return 0x49; // Insert
            case 0x53: return 0x4C; // Delete
            default:
                return 0;
        }
    }

    if (code < table.length)
    {
        return table[code];
    }
    return 0;
}

private void applyModifier(ref HIDKeyboardReport report, ubyte hid, bool pressed) @nogc nothrow
{
    ubyte mask = 0;
    switch (hid)
    {
        case 0xE0: mask = 0x01; break;
        case 0xE1: mask = 0x02; break;
        case 0xE2: mask = 0x04; break;
        case 0xE3: mask = 0x08; break;
        case 0xE4: mask = 0x10; break;
        case 0xE5: mask = 0x20; break;
        case 0xE6: mask = 0x40; break;
        case 0xE7: mask = 0x80; break;
        default:
            break;
    }

    if (mask == 0) return;

    if (pressed) report.modifiers |= mask;
    else report.modifiers &= ~mask;
}

private void addHidKey(ref HIDKeyboardReport report, ubyte hid) @nogc nothrow
{
    foreach (ref slot; report.keycodes)
        if (slot == hid) return;

    foreach (ref slot; report.keycodes)
        if (slot == 0) { slot = hid; return; }
}

private void removeHidKey(ref HIDKeyboardReport report, ubyte hid) @nogc nothrow
{
    foreach (ref slot; report.keycodes)
        if (slot == hid) slot = 0;
}

private void handlePs2KeyboardByte(ubyte data, ref InputQueue queue) @nogc nothrow
{
    if (data == 0xE0)
    {
        g_ps2Extended = true;
        return;
    }

    print("[ps2] kbd: "); printHex(data); printLine("");

    const bool breakCode = (data & 0x80) != 0;
    const ubyte base = cast(ubyte)(data & 0x7F);
    const ubyte hid = mapSet1ToHid(base, g_ps2Extended);
    g_ps2Extended = false;

    if (hid == 0) return;

    applyModifier(g_ps2KeyboardReport, hid, !breakCode);

    if (breakCode) removeHidKey(g_ps2KeyboardReport, hid);
    else addHidKey(g_ps2KeyboardReport, hid);

    g_usbHID.keyboardPresent = true;
    processKeyboardReport(g_ps2KeyboardReport, queue);
}

private void handlePs2MouseByte(ubyte data, ref InputQueue queue) @nogc nothrow
{
    if (data == 0xFA || data == 0xAA) return;

    if (g_ps2MouseIndex == 0 && (data & 0x08) == 0)
        return;

    g_ps2MousePacket[g_ps2MouseIndex++] = data;
    if (g_ps2MouseIndex < 3) return;
    g_ps2MouseIndex = 0;

    const ubyte flags = g_ps2MousePacket[0];
    const ubyte rawX = g_ps2MousePacket[1];
    const ubyte rawY = g_ps2MousePacket[2];
    
    // Check overflow bits - if set, discard this packet
    const bool xOverflow = (flags & 0x40) != 0;
    const bool yOverflow = (flags & 0x80) != 0;
    if (xOverflow || yOverflow)
    {
        // Discard packet with overflow
        return;
    }
    
    // Get sign bits
    const bool xNegative = (flags & 0x10) != 0;
    const bool yNegative = (flags & 0x20) != 0;
    
    // Convert to signed values with proper sign extension
    int deltaX = rawX;
    int deltaY = rawY;
    
    if (xNegative)
    {
        // Sign extend: if negative, set upper bits
        deltaX = cast(int)(rawX | 0xFFFFFF00);
    }
    
    if (yNegative)
    {
        // Sign extend: if negative, set upper bits  
        deltaY = cast(int)(rawY | 0xFFFFFF00);
    }
    
    // PS/2 packet Y is negative when moving down; flip to screen space (positive down)
    deltaY = -deltaY;
    
    // Clamp to reasonable values to prevent jumps
    if (deltaX < -127) deltaX = -127;
    if (deltaX > 127) deltaX = 127;
    if (deltaY < -127) deltaY = -127;
    if (deltaY > 127) deltaY = 127;

    HIDMouseReport report;
    report.buttons = cast(ubyte)(flags & 0x07);
    report.deltaX = cast(byte)deltaX;
    report.deltaY = cast(byte)deltaY;
    report.deltaWheel = 0;

    g_usbHID.pointerPresent = true;
    processMouseReport(report, queue, g_fb.width, g_fb.height);
}

private void pollLegacyPS2(ref InputQueue queue) @nogc nothrow
{
    if (!g_ps2Initialized && !initializeLegacyPS2())
        return;

    static uint pollCount = 0;
    ++pollCount;

    bool sawEvent = false;

    while (g_ps2IsrHead != g_ps2IsrTail)
    {
        const ubyte status = g_ps2IsrStatus[g_ps2IsrHead];
        const ubyte data = g_ps2IsrData[g_ps2IsrHead];
        g_ps2IsrHead = (g_ps2IsrHead + 1) % ps2IsrQueueSize;

        if ((status & ps2StatusIsMouse) != 0)
            handlePs2MouseByte(data, queue);
        else
            handlePs2KeyboardByte(data, queue);

        sawEvent = true;
    }

    while ((inb(ps2StatusPort) & ps2StatusOutputFull) != 0)
    {
        const ubyte status = inb(ps2StatusPort);
        const ubyte data = inb(ps2DataPort);

        // Some controllers may not set the mouse bit; treat bytes with the PS/2
        // packet sync bit (bit 3) set as mouse data.
        if ((status & ps2StatusIsMouse) != 0 || (data & 0x08) != 0)
            handlePs2MouseByte(data, queue);
        else
            handlePs2KeyboardByte(data, queue);

        sawEvent = true;
    }

    // Optional host-driven poll: issue 0xEB to fetch one packet (ACK + 3 bytes)
    // in case the device is in stream mode but not asserting IRQ12.
    if (g_ps2PollingMouse)
    {
        static uint pollThrottle;
        // Poll every 16th iteration to avoid stalling the loop if the device is quiet.
        if ((++pollThrottle & 0x0F) != 0)
        {
            return;
        }

        const ubyte ack = ps2SendMouseCommand(0xEB);
        if (ack == 0xFA)
        {
            ubyte[3] pkt;
            size_t idx = 0;
            while (idx < pkt.length && ps2WaitOutputFull())
            {
                pkt[idx++] = inb(ps2DataPort);
            }
            if (idx == 3)
            {
                g_ps2MousePacket[0] = pkt[0];
                g_ps2MousePacket[1] = pkt[1];
                g_ps2MousePacket[2] = pkt[2];

                HIDMouseReport report;
                report.buttons = cast(ubyte)(g_ps2MousePacket[0] & 0x07);
                report.deltaX = cast(byte)g_ps2MousePacket[1];
                report.deltaY = cast(byte)-cast(byte)g_ps2MousePacket[2];
                report.deltaWheel = 0;
                static ubyte lastButtons;
                if (report.deltaX != 0 || report.deltaY != 0 || report.buttons != lastButtons)
                {
                    lastButtons = report.buttons;
                    print("[ps2] polled packet "); printHex(pkt[0]); print(" "); printHex(pkt[1]); print(" "); printHex(pkt[2]); printLine("");
                }
                g_usbHID.pointerPresent = true;
                processMouseReport(report, queue, g_fb.width, g_fb.height);
                sawEvent = true;
            }
            else
            {
                printLine("[ps2] poll: incomplete packet (timeout while reading)");
            }
        }
        else
        {
            print("[ps2] poll: unexpected ack "); printHex(ack); printLine("");
        }
    }

    static bool announced;
    if (sawEvent && !announced)
    {
        printLine("[usb-hid] PS/2 input active");
        announced = true;
    }
}


// --------------------------------------------------------------------------
// PCI detection + controller init
// --------------------------------------------------------------------------

private enum ushort pciConfigAddress = 0xCF8;
private enum ushort pciConfigData = 0xCFC;

private uint pciConfigRead32(ubyte bus, ubyte slot, ubyte func, ubyte offset) @nogc nothrow
{
    const uint address = (1u << 31) |
                        (cast(uint)bus << 16) |
                        (cast(uint)slot << 11) |
                        (cast(uint)func << 8) |
                        ((cast(uint)offset) & 0xFC);

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

private void pciConfigWrite32(ubyte bus, ubyte slot, ubyte func, ubyte offset, uint value) @nogc nothrow
{
    const uint address = (1u << 31) |
                        (cast(uint)bus << 16) |
                        (cast(uint)slot << 11) |
                        (cast(uint)func << 8) |
                        ((cast(uint)offset) & 0xFC);

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

private ubyte pciConfigRead8(ubyte bus, ubyte slot, ubyte func, ubyte offset) @nogc nothrow
{
    const ubyte aligned = cast(ubyte)(offset & 0xFC);
    const ubyte shift = cast(ubyte)((offset & 0x03) * 8);
    const uint raw = pciConfigRead32(bus, slot, func, aligned);
    return cast(ubyte)((raw >> shift) & 0xFF);
}

private void pciConfigWrite8(ubyte bus, ubyte slot, ubyte func, ubyte offset, ubyte value) @nogc nothrow
{
    const ubyte aligned = cast(ubyte)(offset & 0xFC);
    const ubyte shift = cast(ubyte)((offset & 0x03) * 8);
    uint raw = pciConfigRead32(bus, slot, func, aligned);
    raw &= ~(0xFFu << shift);
    raw |= (cast(uint)value) << shift;
    pciConfigWrite32(bus, slot, func, aligned, raw);
}

private USBControllerType detectUSBController(ref uint busOut,
                                             ref uint slotOut,
                                             ref uint funcOut,
                                             ref ulong mmioBaseOut) @nogc nothrow
{
    USBControllerType detected = USBControllerType.none;
    mmioBaseOut = 0;

    foreach (bus; 0 .. 256)
    {
        foreach (slot; 0 .. 32)
        {
            foreach (func; 0 .. 8)
            {
                const uint vendorDevice = pciConfigRead32(cast(ubyte)bus, cast(ubyte)slot,
                                                         cast(ubyte)func, 0);
                if ((vendorDevice & 0xFFFF) == 0xFFFF)
                {
                    if (func == 0) break;
                    continue;
                }

                const uint classCode = pciConfigRead32(cast(ubyte)bus, cast(ubyte)slot,
                                                      cast(ubyte)func, 8);
                const ubyte baseClass = cast(ubyte)((classCode >> 24) & 0xFF);
                const ubyte subClass = cast(ubyte)((classCode >> 16) & 0xFF);
                const ubyte progIf = cast(ubyte)((classCode >> 8) & 0xFF);

                if (baseClass == 0x0C && subClass == 0x03)
                {
                    busOut = bus;
                    slotOut = slot;
                    funcOut = func;

                    switch (progIf)
                    {
                        case 0x00: detected = USBControllerType.uhci; break;
                        case 0x20: detected = USBControllerType.ehci; break;
                        case 0x30: detected = USBControllerType.xhci; break;
                        default:   detected = USBControllerType.none; break;
                    }

                    // FIX:
                    // EHCI/xHCI often use 64-bit MMIO BARs. UHCI uses I/O BARs.
                    // We only expose MMIO base for EHCI/xHCI.
                    if (detected == USBControllerType.ehci || detected == USBControllerType.xhci)
                    {
                        uint bar0 = pciConfigRead32(cast(ubyte)bus, cast(ubyte)slot,
                                                    cast(ubyte)func, 0x10);
                        uint bar1 = pciConfigRead32(cast(ubyte)bus, cast(ubyte)slot,
                                                    cast(ubyte)func, 0x14);

                        // If BAR is I/O, ignore.
                        if ((bar0 & 0x1) == 0)
                        {
                            ulong mmio = (cast(ulong)bar1 << 32) |
                                          (cast(ulong)(bar0 & 0xFFFF_FFF0));
                            mmioBaseOut = mmio;
                        }
                    }

                    return detected;
                }
            }
        }
    }

    return detected;
}

private bool initializeUHCI(uint bus, uint slot, uint func) @nogc nothrow
{
    // UHCI is I/O-port based. We only enable bus mastering here as a stub.
    const uint commandOffset = 0x04;
    uint command = pciConfigRead32(cast(ubyte)bus, cast(ubyte)slot,
                                   cast(ubyte)func, cast(ubyte)commandOffset);
    command |= 0x0004; // bus master enable
    pciConfigWrite32(cast(ubyte)bus, cast(ubyte)slot,
                     cast(ubyte)func, cast(ubyte)commandOffset, command);
    return (pciConfigRead32(cast(ubyte)bus, cast(ubyte)slot,
                            cast(ubyte)func, cast(ubyte)commandOffset) & 0x0004) == 0x0004;
}

private bool ehciBiosHandoff(uint bus, uint slot, uint func, uint mmioBase) @nogc nothrow
{
    const uint hccparams = mmioRead32(mmioBase, 0x08);
    const ubyte eecp = cast(ubyte)((hccparams >> 8) & 0xFF);
    if (eecp == 0) return true;

    const ubyte capId = pciConfigRead8(cast(ubyte)bus, cast(ubyte)slot,
                                       cast(ubyte)func, eecp);
    if (capId != 1) return true;

    enum ubyte biosSemOffset = 2;
    enum ubyte osSemOffset = 3;

    ubyte osSem = pciConfigRead8(cast(ubyte)bus, cast(ubyte)slot,
                                 cast(ubyte)func, cast(ubyte)(eecp + osSemOffset));
    osSem |= 0x01;
    pciConfigWrite8(cast(ubyte)bus, cast(ubyte)slot,
                    cast(ubyte)func, cast(ubyte)(eecp + osSemOffset), osSem);

    foreach (_; 0 .. 100_000)
    {
        const ubyte biosSem = pciConfigRead8(cast(ubyte)bus, cast(ubyte)slot,
                                             cast(ubyte)func, cast(ubyte)(eecp + biosSemOffset));
        if ((biosSem & 0x01) == 0) return true;
    }

    printLine("[usb-hid] EHCI BIOS ownership handoff timed out");
    return false;
}

private bool initializeEHCI(uint bus, uint slot, uint func, uint mmioBase) @nogc nothrow
{
    if (mmioBase == 0)
    {
        printLine("[usb-hid] EHCI MMIO base missing");
        return false;
    }

    if (!ehciBiosHandoff(bus, slot, func, mmioBase))
        return false;

    const uint commandOffset = 0x04;
    uint command = pciConfigRead32(cast(ubyte)bus, cast(ubyte)slot,
                                   cast(ubyte)func, cast(ubyte)commandOffset);
    command |= 0x0006; // memory + bus master enable
    pciConfigWrite32(cast(ubyte)bus, cast(ubyte)slot,
                     cast(ubyte)func, cast(ubyte)commandOffset, command);

    return (pciConfigRead32(cast(ubyte)bus, cast(ubyte)slot,
                            cast(ubyte)func, cast(ubyte)commandOffset) & 0x0006) == 0x0006;
}

private bool initializeXHCI(uint bus, uint slot, uint func, uint mmioBase) @nogc nothrow
{
    const uint commandOffset = 0x04;
    uint command = pciConfigRead32(cast(ubyte)bus, cast(ubyte)slot,
                                   cast(ubyte)func, cast(ubyte)commandOffset);
    command |= 0x0006; // memory + bus master enable
    pciConfigWrite32(cast(ubyte)bus, cast(ubyte)slot,
                     cast(ubyte)func, cast(ubyte)commandOffset, command);

    if (mmioBase == 0) return false;
    if ((pciConfigRead32(cast(ubyte)bus, cast(ubyte)slot,
                         cast(ubyte)func, cast(ubyte)commandOffset) & 0x0006) != 0x0006)
        return false;

    return initializeXHCIRings(mmioBase);
}

private uint mmioRead32(uint base, uint offset) @nogc nothrow
{
    auto valuePtr = cast(uint*)(base + offset);
    return volatileLoad(valuePtr);
}

private void mmioWrite32(uint base, uint offset, uint value) @nogc nothrow
{
    auto valuePtr = cast(uint*)(base + offset);
    *valuePtr = value;
}


// --------------------------------------------------------------------------
// xHCI rings + transfer parsing (unchanged)
// --------------------------------------------------------------------------

private struct TRB { uint[4] d; }

private bool ringPush(ref XHCIRing ring, const TRB trb) @nogc nothrow
{
    if (ring.enqueueIndex >= ring.size - 1)
    {
        ring.enqueueIndex = 0;
        ring.cycle ^= 1;
    }

    auto dst = &ring.trbs[ring.enqueueIndex];
    *dst = trb;
    dst.d[3] = (dst.d[3] & ~1u) | (ring.cycle & 0x1);

    ++ring.enqueueIndex;
    if (ring.enqueueIndex == ring.size - 1)
    {
        ring.enqueueIndex = 0;
        ring.cycle ^= 1;
    }

    return true;
}

private void ringReset(ref XHCIRing ring) @nogc nothrow
{
    ring.enqueueIndex = 0;
    ring.cycle = 1;

    const uint linkType = 6;
    const uint toggleCycle = 1 << 1;
    auto link = &ring.trbs[ring.size - 1];
    link.d[0] = cast(uint)(ring.phys & 0xFFFF_FFF0);
    link.d[1] = cast(uint)(ring.phys >> 32);
    link.d[2] = 0;
    link.d[3] = (ring.cycle & 0x1) | toggleCycle | (linkType << 10);
}

private void ringDoorbell(uint dbIndex, uint target = 0) @nogc nothrow
{
    const uint db = g_xhci.doorbellBase + dbIndex * 4;
    mmioWrite32(db, 0, target);
}

private bool dequeueEvent(out TRB evt) @nogc nothrow
{
    evt = TRB.init;
    auto er = &g_xhci.eventRing;
    auto ring = &er.ring;

    const auto trb = &ring.trbs[er.dequeueIndex];
    const uint trbCycle = trb.d[3] & 0x1;
    if (trbCycle != er.cycle)
        return false;

    evt = *trb;

    ++er.dequeueIndex;
    if (er.dequeueIndex == ring.size - 1)
    {
        er.dequeueIndex = 0;
        er.cycle ^= 1;
    }

    const uint interrupterBase = g_xhci.runtimeBase + 0x20 * 0;
    updateEventRingDequeue(*er, interrupterBase);
    return true;
}

private HIDDevice* findDeviceByEndpoint(uint slotId, uint endpointId) @nogc nothrow
{
    foreach (ref dev; g_usbHID.devices[0 .. g_usbHID.deviceCount])
    {
        if (dev.enabled && dev.address == slotId && dev.endpoint == endpointId)
            return &dev;
    }
    return null;
}

private void handleEvents(ref InputQueue queue) @nogc nothrow
{
    TRB evt;
    while (dequeueEvent(evt))
    {
        const uint type = (evt.d[3] >> 10) & 0x3F;
        final switch (type)
        {
            case 32:
            {
                const ulong trbPtr = (cast(ulong)evt.d[1] << 32) | (evt.d[0] & 0xFFFF_FFF0);
                const uint completionCode = (evt.d[2] >> 24) & 0xFF;
                const uint residual = evt.d[2] & 0xFFFFFF;
                const uint endpointId = (evt.d[3] >> 16) & 0x1F;
                const uint slotId = (evt.d[3] >> 24) & 0xFF;

                print("[usb-hid] Transfer event slot=");
                printHex(slotId);
                print(" ep=");
                printHex(endpointId);
                print(" cc=");
                printHex(completionCode);
                print(" resid=");
                printHex(residual);
                print(" trb=");
                printHex(cast(uint)trbPtr);
                printLine("");

                if (endpointId != 1)
                    parseHidTransfer(trbPtr, residual, endpointId, slotId, queue);
                break;
            }
            case 33:
            {
                const uint completionCode = (evt.d[2] >> 24) & 0xFF;
                const uint slotId = (evt.d[3] >> 24) & 0xFF;
                print("[usb-hid] Cmd completion cc=");
                printHex(completionCode);
                print(" slot=");
                printHex(slotId);
                printLine("");
                break;
            }
            case 34:
            {
                const uint portId = (evt.d[0] & 0xFF);
                const uint portscOffset = 0x400 + 0x10 * (portId - 1);
                uint portsc = mmioRead32(g_xhci.opBase, portscOffset);
                portsc |= (1u << 1)
                       | (1u << 17)
                       | (1u << 21)
                       | (1u << 18)
                       | (1u << 20);
                mmioWrite32(g_xhci.opBase, portscOffset, portsc);

                print("[usb-hid] Port status change port=");
                printHex(portId);
                printLine("");
                break;
            }
        }
    }
}

private bool waitForCommandCompletion(ulong cmdPhys, out uint completionCode, out uint slotId) @nogc nothrow
{
    completionCode = 0xFF;
    slotId = 0;

    foreach (_; 0 .. 100_000)
    {
        TRB evt;
        if (!dequeueEvent(evt))
            continue;

        const uint type = (evt.d[3] >> 10) & 0x3F;
        if (type != 33)
            continue;

        const ulong cmdPtr = (cast(ulong)evt.d[1] << 32) | (evt.d[0] & 0xFFFF_FFF0);
        completionCode = (evt.d[2] >> 24) & 0xFF;
        slotId = (evt.d[3] >> 24) & 0xFF;

        if (cmdPtr == cmdPhys)
            return true;
    }

    printLine("[usb-hid] Command completion timed out");
    return false;
}

private bool submitEnableSlot(out uint slotId) @nogc nothrow
{
    slotId = 0;
    TRB cmd;
    cmd.d[0] = 0;
    cmd.d[1] = 0;
    cmd.d[2] = 0;
    const uint typeEnableSlot = 9;
    cmd.d[3] = (typeEnableSlot << 10);

    const ulong cmdPhys = g_xhci.commandRing.phys + cast(ulong)(g_xhci.commandRing.enqueueIndex * TRB.sizeof);
    if (!ringPush(g_xhci.commandRing, cmd))
    {
        printLine("[usb-hid] Failed to enqueue Enable Slot");
        return false;
    }

    ringDoorbell(0, 0);

    uint ccode;
    uint sid;
    if (!waitForCommandCompletion(cmdPhys, ccode, sid))
        return false;

    if (ccode != 1)
    {
        printLine("[usb-hid] Enable Slot completion error");
        return false;
    }

    slotId = sid;
    return true;
}

private bool submitAddressDevice(uint slotId, ulong inputContextPhys) @nogc nothrow
{
    TRB cmd;
    cmd.d[0] = cast(uint)(inputContextPhys & 0xFFFF_FFF0);
    cmd.d[1] = cast(uint)(inputContextPhys >> 32);
    cmd.d[2] = 0;
    const uint typeAddressDevice = 11;
    cmd.d[3] = (typeAddressDevice << 10) | (slotId & 0xFF);

    const ulong cmdPhys = g_xhci.commandRing.phys + cast(ulong)(g_xhci.commandRing.enqueueIndex * TRB.sizeof);
    if (!ringPush(g_xhci.commandRing, cmd))
    {
        printLine("[usb-hid] Failed to enqueue Address Device");
        return false;
    }
    ringDoorbell(0, 0);

    uint ccode;
    uint sid;
    if (!waitForCommandCompletion(cmdPhys, ccode, sid))
        return false;

    if (ccode != 1 || sid != slotId)
    {
        printLine("[usb-hid] Address Device completion error");
        return false;
    }
    return true;
}

private bool setupEndpointContexts(uint slotId) @nogc nothrow
{
    if (g_xhci.dcbaa is null)
        return false;

    if (g_xhci.deviceContextPhys == 0)
    {
        auto devCtx = dma_alloc(1024, 64, &g_xhci.deviceContextPhys);
        if (devCtx is null)
        {
            printLine("[usb-hid] Device context alloc failed");
            return false;
        }
        g_xhci.dcbaa[slotId] = g_xhci.deviceContextPhys;
    }

    if (g_xhci.inputContextPhys == 0)
    {
        auto inpCtx = dma_alloc(1024, 64, &g_xhci.inputContextPhys);
        if (inpCtx is null)
        {
            printLine("[usb-hid] Input context alloc failed");
            return false;
        }
    }

    if (!allocateTrbRing(256, g_xhci.ep0Ring))
    {
        printLine("[usb-hid] EP0 ring alloc failed");
        return false;
    }

    auto inp = cast(uint*)(cast(ulong)g_xhci.inputContextPhys);
    inp[0] = 0x00000003;
    inp[8 + 0] = 0;
    inp[8 + 1] = (1 << 27);
    inp[8 + 3] = 0;

    size_t ep0Offset = 32;
    const uint epTypeControl = 4;
    inp[ep0Offset + 0] = (8 << 16) | (3 << 10) | (1 << 0);
    inp[ep0Offset + 1] = (epTypeControl << 3);
    const ulong trDeq = g_xhci.ep0Ring.phys | (g_xhci.ep0Ring.cycle & 0x1);
    inp[ep0Offset + 2] = cast(uint)(trDeq & 0xFFFF_FFFF);
    inp[ep0Offset + 3] = cast(uint)(trDeq >> 32);
    inp[ep0Offset + 4] = 0;

    return submitAddressDevice(slotId, g_xhci.inputContextPhys);
}

private bool waitForTransferCompletion(ulong trbPhys, out uint completionCode, out uint residual) @nogc nothrow
{
    completionCode = 0xFF;
    residual = 0;
    foreach (_; 0 .. 100_000)
    {
        TRB evt;
        if (!dequeueEvent(evt))
            continue;

        const uint type = (evt.d[3] >> 10) & 0x3F;
        if (type != 32)
            continue;

        const ulong ptr = (cast(ulong)evt.d[1] << 32) | (evt.d[0] & 0xFFFF_FFF0);
        completionCode = (evt.d[2] >> 24) & 0xFF;
        residual = evt.d[2] & 0xFFFFFF;
        if (ptr == trbPhys)
            return true;
    }
    return false;
}

private ushort readLe16(const ubyte* p) @nogc nothrow pure
{
    return cast(ushort)(p[0] | (p[1] << 8));
}

private struct USBDeviceDescriptor
{
    ubyte bLength;
    ubyte bDescriptorType;
    ushort bcdUSB;
    ubyte bDeviceClass;
    ubyte bDeviceSubClass;
    ubyte bDeviceProtocol;
    ubyte bMaxPacketSize0;
    ushort idVendor;
    ushort idProduct;
    ushort bcdDevice;
    ubyte iManufacturer;
    ubyte iProduct;
    ubyte iSerialNumber;
    ubyte bNumConfigurations;
}

private struct HIDEndpointInfo
{
    HIDDeviceType devType;
    ubyte endpoint;
    ubyte interval;
    ubyte maxPacket;
}

private bool controlGetDescriptor(uint slotId, ubyte descType, ubyte descIndex,
                                 ushort length, out ubyte* outBuf, out uint outLen) @nogc nothrow
{
    outBuf = null;
    outLen = 0;

    ringReset(g_xhci.ep0Ring);

    const ubyte bmRequestType = 0x80;
    const ubyte bRequest = 6;
    const ushort wValue = cast(ushort)((descType << 8) | descIndex);
    const ushort wIndex = 0;

    TRB setup;
    setup.d[0] = (cast(uint)wValue << 16) | (cast(uint)bRequest << 8) | bmRequestType;
    setup.d[1] = (cast(uint)length << 16) | wIndex;
    setup.d[2] = 0;
    const uint trbTypeSetup = 2;
    setup.d[3] = (trbTypeSetup << 10) | (1 << 6);
    if (!ringPush(g_xhci.ep0Ring, setup))
        return false;

    ulong dataPhys;
    auto dataBuf = cast(ubyte*)dma_alloc(length, 64, &dataPhys);
    if (dataBuf is null)
        return false;

    TRB data;
    data.d[0] = cast(uint)(dataPhys & 0xFFFF_FFFF);
    data.d[1] = cast(uint)(dataPhys >> 32);
    data.d[2] = length;
    const uint trbTypeData = 3;
    data.d[3] = (trbTypeData << 10) | (1 << 16);
    if (!ringPush(g_xhci.ep0Ring, data))
        return false;

    TRB status;
    status.d[0] = 0;
    status.d[1] = 0;
    status.d[2] = 0;
    const uint trbTypeStatus = 4;
    status.d[3] = (trbTypeStatus << 10);

    const ulong statusPhys = g_xhci.ep0Ring.phys + cast(ulong)(g_xhci.ep0Ring.enqueueIndex * TRB.sizeof);
    if (!ringPush(g_xhci.ep0Ring, status))
        return false;

    ringDoorbell(slotId, 1);

    uint ccode;
    uint residual;
    if (!waitForTransferCompletion(statusPhys, ccode, residual))
        return false;

    if (ccode != 1)
        return false;

    const uint transferred = (length > residual) ? (length - residual) : length;
    outBuf = dataBuf;
    outLen = transferred;
    return true;
}

private bool fetchDeviceDescriptor(uint slotId, out USBDeviceDescriptor desc) @nogc nothrow
{
    desc = USBDeviceDescriptor.init;
    ubyte* buf;
    uint len;
    if (!controlGetDescriptor(slotId, 1, 0, 18, buf, len)) return false;
    if (len < 18) return false;

    desc.bLength = buf[0];
    desc.bDescriptorType = buf[1];
    desc.bcdUSB = readLe16(buf + 2);
    desc.bDeviceClass = buf[4];
    desc.bDeviceSubClass = buf[5];
    desc.bDeviceProtocol = buf[6];
    desc.bMaxPacketSize0 = buf[7];
    desc.idVendor = readLe16(buf + 8);
    desc.idProduct = readLe16(buf + 10);
    desc.bcdDevice = readLe16(buf + 12);
    desc.iManufacturer = buf[14];
    desc.iProduct = buf[15];
    desc.iSerialNumber = buf[16];
    desc.bNumConfigurations = buf[17];
    return true;
}

private bool fetchConfigurationDescriptor(uint slotId, ubyte configIndex,
                                         out ubyte* cfgBuf, out uint cfgLen) @nogc nothrow
{
    cfgBuf = null;
    cfgLen = 0;

    ubyte* headBuf;
    uint headLen;
    if (!controlGetDescriptor(slotId, 2, configIndex, 9, headBuf, headLen))
        return false;
    if (headLen < 9)
        return false;

    const uint totalLen = readLe16(headBuf + 2);
    const uint cappedLen = (totalLen > 512) ? 512 : totalLen;

    if (!controlGetDescriptor(slotId, 2, configIndex, cast(ushort)cappedLen, cfgBuf, cfgLen))
        return false;

    return cfgLen >= 9;
}

private bool parseHidFromConfig(const ubyte* buf, uint len, out HIDEndpointInfo info) @nogc nothrow
{
    info = HIDEndpointInfo.init;
    if (buf is null || len < 9) return false;

    HIDDeviceType currentType = HIDDeviceType.none;
    uint index = 0;
    while (index + 2 <= len)
    {
        const ubyte bLength = buf[index];
        const ubyte bDescriptorType = buf[index + 1];
        if (bLength == 0 || index + bLength > len) break;

        if (bDescriptorType == 4 && bLength >= 9)
        {
            const ubyte interfaceClass = buf[index + 5];
            const ubyte interfaceSub = buf[index + 6];
            const ubyte protocol = buf[index + 7];
            if (interfaceClass == 0x03)
            {
                if (interfaceSub == 0x01 && protocol == 0x02)
                    currentType = HIDDeviceType.mouse;
                else
                    currentType = HIDDeviceType.keyboard;
            }
            else currentType = HIDDeviceType.none;
        }
        else if (bDescriptorType == 5 && bLength >= 7 && currentType != HIDDeviceType.none)
        {
            const ubyte epAddr = buf[index + 2];
            const ubyte attributes = buf[index + 3];
            const ubyte maxPacket = buf[index + 4];
            const ubyte interval = buf[index + 6];
            const bool isInterrupt = (attributes & 0x3) == 0x3;
            const bool isIn = (epAddr & 0x80) != 0;
            if (isInterrupt && isIn)
            {
                info.devType = currentType;
                info.endpoint = epAddr;
                info.interval = interval;
                info.maxPacket = maxPacket;
                return true;
            }
        }

        index += bLength;
    }

    return false;
}

private void parseKeyboardReportFromBuffer(const ubyte* buf, uint len, ref InputQueue queue) @nogc nothrow
{
    if (len < 8) return;
    HIDKeyboardReport report = HIDKeyboardReport.init;
    report.modifiers = buf[0];
    foreach (i; 0 .. report.keycodes.length)
        report.keycodes[i] = buf[2 + i];
    processKeyboardReport(report, queue);
}

private void parseMouseReportFromBuffer(const ubyte* buf, uint len, ref InputQueue queue) @nogc nothrow
{
    if (len < 3) return;
    HIDMouseReport report = HIDMouseReport.init;
    report.buttons = cast(ubyte)(buf[0] & 0x07);
    report.deltaX = cast(byte)buf[1];
    report.deltaY = cast(byte)buf[2];
    if (len > 3) report.deltaWheel = cast(byte)buf[3];
    processMouseReport(report, queue, g_fb.width, g_fb.height);
}

private void parseHidTransfer(ulong trbPtr, uint residual, uint endpointId,
                             uint slotId, ref InputQueue queue) @nogc nothrow
{
    auto trb = cast(TRB*)trbPtr;
    if (trb is null) return;

    const uint trbType = (trb.d[3] >> 10) & 0x3F;
    if (trbType != 1 && trbType != 3) return;

    const ulong bufPhys = (cast(ulong)trb.d[1] << 32) | (trb.d[0] & 0xFFFF_FFF0);
    const uint requestedLen = trb.d[2] & 0x1FFFF;
    const uint actualLen = (requestedLen > residual) ? (requestedLen - residual) : requestedLen;
    if (bufPhys == 0 || actualLen == 0) return;

    auto buf = cast(const ubyte*)bufPhys;

    HIDDeviceType devType = HIDDeviceType.none;
    if (auto dev = findDeviceByEndpoint(slotId, endpointId))
        devType = dev.deviceType;

    // Heuristic fallback if endpoint info missing.
    if (devType == HIDDeviceType.keyboard || actualLen >= 8)
        parseKeyboardReportFromBuffer(buf, actualLen, queue);
    else if (devType == HIDDeviceType.mouse || actualLen >= 3)
        parseMouseReportFromBuffer(buf, actualLen, queue);
}

private bool submitControlTransferGetDescriptor(uint slotId) @nogc nothrow
{
    const ubyte bmRequestType = 0x80;
    const ubyte bRequest = 6;
    const ushort wValue = 0x0100;
    const ushort wIndex = 0;
    const ushort wLength = 18;

    TRB setup;
    setup.d[0] = (cast(uint)wValue << 16) | (cast(uint)bRequest << 8) | bmRequestType;
    setup.d[1] = (cast(uint)wLength << 16) | wIndex;
    setup.d[2] = 0;
    const uint trbTypeSetup = 2;
    setup.d[3] = (trbTypeSetup << 10) | (1 << 6);
    if (!ringPush(g_xhci.ep0Ring, setup)) return false;

    ulong dataPhys;
    auto dataBuf = cast(ubyte*)dma_alloc(wLength, 64, &dataPhys);
    if (dataBuf is null) return false;

    TRB data;
    data.d[0] = cast(uint)(dataPhys & 0xFFFF_FFFF);
    data.d[1] = cast(uint)(dataPhys >> 32);
    data.d[2] = wLength;
    const uint trbTypeData = 3;
    data.d[3] = (trbTypeData << 10) | (1 << 16);
    if (!ringPush(g_xhci.ep0Ring, data)) return false;

    TRB status;
    status.d[0] = status.d[1] = status.d[2] = 0;
    const uint trbTypeStatus = 4;
    status.d[3] = (trbTypeStatus << 10);

    const ulong statusPhys = g_xhci.ep0Ring.phys + cast(ulong)(g_xhci.ep0Ring.enqueueIndex * TRB.sizeof);
    if (!ringPush(g_xhci.ep0Ring, status)) return false;

    ringDoorbell(slotId, 1);

    uint ccode, residual;
    if (!waitForTransferCompletion(statusPhys, ccode, residual))
    {
        printLine("[usb-hid] Control transfer timed out");
        return false;
    }
    if (ccode != 1)
    {
        print("[usb-hid] Control transfer failed cc=");
        printHex(ccode);
        printLine("");
        return false;
    }

    printLine("[usb-hid] Device descriptor received");
    return true;
}

private struct ERSTEntry
{
    ulong ringBase;
    uint  ringSize;
    uint  reserved;
}

private struct XHCIRing
{
    TRB*  trbs;
    ulong phys;
    uint  size;
    uint  enqueueIndex;
    uint  cycle;
}

private struct XHCIEventRing
{
    XHCIRing   ring;
    ERSTEntry* erst;
    ulong      erstPhys;
    uint       dequeueIndex;
    uint       cycle;
}

private struct XHCIState
{
    uint mmioBase;
    uint opBase;
    uint runtimeBase;
    uint doorbellBase;
    uint maxSlots;
    uint hcsParams1;
    uint hcsParams2;
    XHCIRing commandRing;
    XHCIEventRing eventRing;
    ulong dcbaaPhys;
    ulong scratchArrayPhys;
    ulong* dcbaa;
    ulong deviceContextPhys;
    ulong inputContextPhys;
    XHCIRing ep0Ring;
    uint lastSlotId;
}

__gshared XHCIState g_xhci;

// Forward declaration for xHCI setup
private bool initializeXHCIRings(uint mmioBase) @nogc nothrow;

private const(char)[] controllerTypeName(USBControllerType type) @nogc nothrow pure
{
    final switch (type)
    {
        case USBControllerType.none: return "none";
        case USBControllerType.uhci: return "UHCI (USB 1.1)";
        case USBControllerType.ehci: return "EHCI (USB 2.0)";
        case USBControllerType.xhci: return "XHCI (USB 3.0+)";
    }
}


// --------------------------------------------------------------------------
// Public API
// --------------------------------------------------------------------------

__gshared USBHIDSubsystem g_usbHID;

void initializeUSBHID() @nogc nothrow
{
    g_usbHID.initialize();
}

void pollUSBHID(ref InputQueue queue) @nogc nothrow
{
    g_usbHID.poll(queue);
}

bool usbHIDAvailable() @nogc nothrow
{
    // “Available” now means the subsystem has been set up (USB and/or PS/2).
    // Higher layers should use usbHIDPointerPresent/KeyboardPresent to know
    // whether any real device is live.
    return g_usbHID.initialized;
}

bool usbHIDPointerPresent() @nogc nothrow
{
    return g_usbHID.pointerPresent;
}

bool usbHIDTouchPresent() @nogc nothrow
{
    return g_usbHID.touchPresent;
}

bool usbHIDKeyboardPresent() @nogc nothrow
{
    return g_usbHID.keyboardPresent;
}
