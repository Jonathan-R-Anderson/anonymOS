module minimal_os.drivers.usb_hid;

import minimal_os.console : print, printLine, printHex, printUnsigned;
import minimal_os.display.input_pipeline : InputQueue, enqueue, InputEvent;
import minimal_os.drivers.hid_keyboard : HIDKeyboardReport, processKeyboardReport;
import minimal_os.drivers.hid_mouse : HIDMouseReport, processMouseReport;

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
    uint controllerMmioBase;
    bool initialized;
    HIDDevice[8] devices;
    ubyte deviceCount;
    bool pointerPresent;
    bool touchPresent;
    bool keyboardPresent;
    size_t keyboardMockIndex;
    size_t mouseMockIndex;
    
    void initialize()
    {
        printLine("[usb-hid] Initializing USB HID subsystem...");

        pointerPresent = false;
        touchPresent = false;
        keyboardPresent = false;
        keyboardMockIndex = 0;
        mouseMockIndex = 0;
        controllerMmioBase = 0;

        // Detect USB controllers
        controllerType = detectUSBController(controllerBus, controllerSlot, controllerFunction, controllerMmioBase);

        if (controllerType == USBControllerType.none)
        {
            printLine("[usb-hid] No USB controllers detected");
            initialized = false;
            return;
        }
        
        print("[usb-hid] Found controller: ");
        printLine(controllerTypeName(controllerType));
        
        // Initialize the controller
        if (!initializeController())
        {
            printLine("[usb-hid] Failed to initialize USB controller");
            initialized = false;
            return;
        }
        
        // Enumerate HID devices
        enumerateHIDDevices();
        
        print("[usb-hid] Detected ");
        printUnsigned(deviceCount);
        printLine(" HID device(s)");

        initialized = true;
    }
    
    void poll(ref InputQueue queue)
    {
        if (!initialized)
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
    }
    
    private bool initializeController()
    {
        final switch (controllerType)
        {
            case USBControllerType.uhci:
                return initializeUHCI(controllerBus, controllerSlot, controllerFunction);
            case USBControllerType.ehci:
                return initializeEHCI(controllerBus, controllerSlot, controllerFunction);
            case USBControllerType.xhci:
                return initializeXHCI(controllerBus, controllerSlot, controllerFunction, controllerMmioBase);
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
        // This is device-type specific
        
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
    
    private void pollKeyboard(ref HIDDevice device, ref InputQueue queue)
    {
        // TODO: submit transfer descriptors and parse real HID keyboard reports
        // when a complete USB host stack is available.
    }

    private void pollMouse(ref HIDDevice device, ref InputQueue queue)
    {
        // TODO: submit transfer descriptors and parse real HID mouse reports
        // when a complete USB host stack is available.
    }
}

private enum uint pciConfigAddress = 0xCF8;
private enum uint pciConfigData = 0xCFC;

private void outl(uint port, uint value) @nogc nothrow
{
    asm
    {
        "mov DX, %[port];"
        "mov EAX, %[value];"
        "out DX, EAX;"
        :
        : [port] "r" (port), [value] "r" (value)
        : "eax", "dx";
    }
}

private uint inl(uint port) @nogc nothrow
{
    uint value;
    asm
    {
        "mov DX, %[port];"
        "in EAX, DX;"
        "mov %[value], EAX;"
        : [value] "=r" (value)
        : [port] "r" (port)
        : "eax", "dx";
    }
    return value;
}

private uint pciConfigRead32(ubyte bus, ubyte slot, ubyte func, ubyte offset) @nogc nothrow
{
    const uint address = (cast(uint)bus << 16) | (cast(uint)slot << 11) | (cast(uint)func << 8) | (offset & 0xFC) | 0x8000_0000;
    outl(pciConfigAddress, address);
    return inl(pciConfigData);
}

private void pciConfigWrite32(ubyte bus, ubyte slot, ubyte func, ubyte offset, uint value) @nogc nothrow
{
    const uint address = (cast(uint)bus << 16) | (cast<uint)slot << 11) | (cast<uint)func << 8) | (offset & 0xFC) | 0x8000_0000;
    outl(pciConfigAddress, address);
    outl(pciConfigData, value);
}

private USBControllerType detectUSBController(ref uint busOut, ref uint slotOut, ref uint funcOut, ref uint mmioBaseOut) @nogc nothrow
{
    USBControllerType detected = USBControllerType.none;
    mmioBaseOut = 0;

    foreach (bus; 0 .. 256)
    {
        foreach (slot; 0 .. 32)
        {
            foreach (func; 0 .. 8)
            {
                const uint vendorDevice = pciConfigRead32(cast(ubyte)bus, cast(ubyte)slot, cast(ubyte)func, 0);
                if ((vendorDevice & 0xFFFF) == 0xFFFF)
                {
                    if (func == 0)
                    {
                        break;
                    }
                    continue;
                }

                const uint classCode = pciConfigRead32(cast(ubyte)bus, cast(ubyte)slot, cast(ubyte)func, 8);
                const ubyte baseClass = cast(ubyte)((classCode >> 24) & 0xFF);
                const ubyte subClass = cast(ubyte)((classCode >> 16) & 0xFF);
                const ubyte progIf = cast(ubyte)((classCode >> 8) & 0xFF);

                if (baseClass == 0x0C && subClass == 0x03)
                {
                    busOut = bus;
                    slotOut = slot;
                    funcOut = func;

                    final switch (progIf)
                    {
                        case 0x00:
                            detected = USBControllerType.uhci;
                            break;
                        case 0x20:
                            detected = USBControllerType.ehci;
                            break;
                        case 0x30:
                            detected = USBControllerType.xhci;
                            break;
                        default:
                            detected = USBControllerType.none;
                            break;
                    }

                    const uint bar0 = pciConfigRead32(cast(ubyte)bus, cast(ubyte)slot, cast(ubyte)func, 0x10);
                    mmioBaseOut = bar0 & 0xFFFF_FFF0;

                    return detected;
                }
            }
        }
    }

    return detected;
}

private bool initializeUHCI(uint bus, uint slot, uint func) @nogc nothrow
{
    const uint commandOffset = 0x04;
    uint command = pciConfigRead32(cast(ubyte)bus, cast(ubyte)slot, cast(ubyte)func, cast(ubyte)commandOffset);
    command |= 0x0006; // memory + bus master enable
    pciConfigWrite32(cast(ubyte)bus, cast(ubyte)slot, cast(ubyte)func, cast(ubyte)commandOffset, command);
    return (pciConfigRead32(cast(ubyte)bus, cast(ubyte)slot, cast(ubyte)func, cast(ubyte)commandOffset) & 0x0006) == 0x0006;
}

private bool initializeEHCI(uint bus, uint slot, uint func) @nogc nothrow
{
    const uint commandOffset = 0x04;
    uint command = pciConfigRead32(cast(ubyte)bus, cast(ubyte)slot, cast(ubyte)func, cast(ubyte)commandOffset);
    command |= 0x0006; // memory + bus master enable
    pciConfigWrite32(cast(ubyte)bus, cast(ubyte)slot, cast(ubyte)func, cast(ubyte)commandOffset, command);
    return (pciConfigRead32(cast(ubyte)bus, cast(ubyte)slot, cast(ubyte)func, cast(ubyte)commandOffset) & 0x0006) == 0x0006;
}

private bool initializeXHCI(uint bus, uint slot, uint func, uint mmioBase) @nogc nothrow
{
    const uint commandOffset = 0x04;
    uint command = pciConfigRead32(cast(ubyte)bus, cast(ubyte)slot, cast(ubyte)func, cast(ubyte)commandOffset);
    command |= 0x0006; // memory + bus master enable
    pciConfigWrite32(cast(ubyte)bus, cast(ubyte)slot, cast(ubyte)func, cast(ubyte)commandOffset, command);

    // Ensure the MMIO base is valid
    return mmioBase != 0 && (pciConfigRead32(cast(ubyte)bus, cast(ubyte)slot, cast(ubyte)func, cast(ubyte)commandOffset) & 0x0006) == 0x0006;
}

private uint mmioRead32(uint base, uint offset) @nogc nothrow
{
    return *cast(volatile uint*)(base + offset);
}

private void enumerateXHCIDevices() @nogc nothrow
{
    if (controllerMmioBase == 0)
    {
        printLine("[usb-hid] No MMIO base for XHCI; skipping enumeration");
        return;
    }

    const uint capLength = *cast(volatile ubyte*)controllerMmioBase;
    const uint hcsParams1 = mmioRead32(controllerMmioBase, 0x04);
    const uint portCount = (hcsParams1 >> 24) & 0xFF;
    const uint portBase = controllerMmioBase + capLength + 0x400; // port register set base

    foreach (portIndex; 0 .. portCount)
    {
        const uint portStatus = mmioRead32(portBase, portIndex * 0x10);
        const bool connected = (portStatus & 0x01) != 0;
        if (!connected)
        {
            continue;
        }

        if (deviceCount >= devices.length)
        {
            break;
        }

        const uint speed = (portStatus >> 10) & 0x0F;

        // Heuristic: low/full speed devices are commonly HID keyboards, higher
        // speeds are more likely to be pointer-class devices when running
        // under common virtualization setups.
        HIDDeviceType detectedType = (speed <= 0x02) ? HIDDeviceType.keyboard : HIDDeviceType.mouse;

        auto device = &devices[deviceCount];
        device.deviceType = detectedType;
        device.enabled = false; // endpoints are not configured yet
        device.address = cast(ubyte)(portIndex + 1);
        device.endpoint = 0;
        device.vendorId = 0;
        device.productId = 0;

        deviceCount++;
        if (detectedType == HIDDeviceType.keyboard)
        {
            keyboardPresent = true;
        }
        else
        {
            pointerPresent = true;
        }
    }
}

private const(char)[] controllerTypeName(USBControllerType type) @nogc nothrow pure
{
    final switch (type)
    {
        case USBControllerType.none:
            return "none";
        case USBControllerType.uhci:
            return "UHCI (USB 1.1)";
        case USBControllerType.ehci:
            return "EHCI (USB 2.0)";
        case USBControllerType.xhci:
            return "XHCI (USB 3.0+)";
    }
}

// Global USB HID subsystem instance
__gshared USBHIDSubsystem g_usbHID;

/// Initialize the USB HID subsystem
void initializeUSBHID() @nogc nothrow
{
    g_usbHID.initialize();
}

/// Poll all USB HID devices and fill the input queue
void pollUSBHID(ref InputQueue queue) @nogc nothrow
{
    g_usbHID.poll(queue);
}

/// Check if USB HID is available
bool usbHIDAvailable() @nogc nothrow
{
    return g_usbHID.initialized;
}

/// Report whether a pointer-class HID device (mouse, touchpad, etc.) is online
bool usbHIDPointerPresent() @nogc nothrow
{
    return g_usbHID.pointerPresent;
}

/// Report whether a touch digitizer was enumerated
bool usbHIDTouchPresent() @nogc nothrow
{
    return g_usbHID.touchPresent;
}

/// Report whether a keyboard HID device was discovered
bool usbHIDKeyboardPresent() @nogc nothrow
{
    return g_usbHID.keyboardPresent;
}
