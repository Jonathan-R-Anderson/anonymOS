module minimal_os.kernel.exceptions;

import minimal_os.console : printLine;

nothrow:
@nogc:

extern(C) void handleInvalidOpcode()
{
    printLine("");
    printLine("[fault] Invalid opcode encountered by CPU.");
    printLine("[halt] System halted to prevent undefined behaviour.");

    for (;;)
    {
    }
}
