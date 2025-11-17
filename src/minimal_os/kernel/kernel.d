module minimal_os.kernel.kernel;

public import minimal_os.kernel.memory;

import minimal_os.console : clearScreen;
import minimal_os.serial : initSerial;
import minimal_os.hardware : probeHardware;
import minimal_os.kernel.shell_integration : runCompilerBuilder, posixInit, initializeInterrupts;

/// Entry point invoked from boot.s once the CPU is ready to run D code.
/// Initialises the VGA output and runs the compiler build program.
extern(C) void kmain(ulong magic, ulong info)
{
    cast(void) magic;
    cast(void) info;

    clearScreen();
    initSerial();
    probeHardware(magic, info);
    initializeInterrupts();

    posixInit();
    runCompilerBuilder();
}
