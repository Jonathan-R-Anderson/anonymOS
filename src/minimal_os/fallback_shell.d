module minimal_os.fallback_shell;

import minimal_os.console : print, printLine;
import minimal_os.serial : serialConsoleReady, serialReadByteBlocking, serialWriteByte;

extern(C) @nogc nothrow void _exit(int code);

private enum size_t LINE_CAPACITY = 256;
private enum char PROMPT_CHAR = '#';

@nogc nothrow private size_t readLine(out char[LINE_CAPACITY] buffer)
{
    size_t length = 0;
    bool seenCarriageReturn = false;

    for (;;)
    {
        const char ch = serialReadByteBlocking();

        if (ch == '\r')
        {
            seenCarriageReturn = true;
            printLine("");
            break;
        }

        if (ch == '\n')
        {
            if (!seenCarriageReturn)
            {
                printLine("");
            }
            break;
        }

        if (ch == '\b' || ch == 0x7F)
        {
            if (length > 0)
            {
                --length;
                serialWriteByte('\b');
                serialWriteByte(' ');
                serialWriteByte('\b');
            }
            continue;
        }

        if (length + 1 >= buffer.length)
        {
            continue;
        }

        buffer[length++] = ch;
        serialWriteByte(cast(ubyte)ch);
    }

    buffer[length] = '\0';
    return length;
}

@nogc nothrow private immutable(char)[] trim(immutable(char)[] text)
{
    size_t start = 0;
    size_t finish = text.length;

    while (start < finish && (text[start] == ' ' || text[start] == '\t'))
    {
        ++start;
    }

    while (finish > start && (text[finish - 1] == ' ' || text[finish - 1] == '\t'))
    {
        --finish;
    }

    return text[start .. finish];
}

@nogc nothrow private bool startsWith(immutable(char)[] text, immutable(char)[] prefix)
{
    if (text.length < prefix.length)
    {
        return false;
    }

    foreach (index, ch; prefix)
    {
        if (text[index] != ch)
        {
            return false;
        }
    }

    return true;
}

@nogc nothrow private void printPrompt()
{
    print("lfe-sh");
    print(" ");
    printChar(PROMPT_CHAR);
    print(" ");
}

@nogc nothrow private void printChar(char value)
{
    serialWriteByte(cast(ubyte)value);
}

@nogc nothrow private void printLineImmediate(const(char)[] text)
{
    foreach (ch; text)
    {
        serialWriteByte(cast(ubyte)ch);
    }
    serialWriteByte('\r');
    serialWriteByte('\n');
}

@nogc nothrow private void executeEcho(immutable(char)[] payload)
{
    if (payload.length == 0)
    {
        printLineImmediate("");
        return;
    }

    printLineImmediate(payload);
}

@nogc nothrow private void printHelp()
{
    printLineImmediate("Available commands:");
    printLineImmediate("  help  - Show this message");
    printLineImmediate("  echo  - Echo the provided text");
    printLineImmediate("  clear - Add a blank line");
    printLineImmediate("  exit  - Leave the shell");
}

@nogc nothrow public void runFallbackShell()
{
    if (!serialConsoleReady())
    {
        printLine("[shell] Serial console unavailable; fallback shell cannot start.");
        _exit(127);
    }

    printLine("[shell] POSIX utilities missing; launching minimal fallback shell.");
    printLine("[shell] Type 'help' for available commands.");

    char[LINE_CAPACITY] lineBuffer;

    for (;;)
    {
        printPrompt();
        const size_t length = readLine(lineBuffer);
        immutable(char)[] raw = cast(immutable(char)[])lineBuffer[0 .. length];
        immutable(char)[] command = trim(raw);

        if (command.length == 0)
        {
            continue;
        }

        if (command == "help")
        {
            printHelp();
            continue;
        }

        if (command == "clear")
        {
            printLineImmediate("");
            continue;
        }

        if (command == "exit")
        {
            printLine("[shell] Exiting fallback shell.");
            _exit(0);
        }

        if (startsWith(command, "echo "))
        {
            immutable(char)[] payload = trim(command[5 .. $]);
            executeEcho(payload);
            continue;
        }

        if (command == "xinit" || command == "startx" || command == "i3")
        {
            printLine("[shell] Error: External binary not found.");
            printLine("[shell] The ELF loader is active, but the filesystem is empty.");
            printLine("[shell] Ensure binaries are loaded into the VFS.");
            continue;
        }

        print("[shell] Unknown command: ");
        printLineImmediate(command);
    }
}
