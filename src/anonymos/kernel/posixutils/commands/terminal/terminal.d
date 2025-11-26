module commands.terminal.terminal;

import core.sys.posix.unistd;
import core.sys.posix.fcntl;
import core.sys.posix.sys.wait;
import std.stdio;
import std.process;
import std.string;
import std.conv;
import std.file;

// X11 Protocol Constants (simplified)
enum X11Opcode : ubyte
{
    CreateWindow = 1,
    MapWindow = 8,
    PolyFillRectangle = 70,
    // ... others
}

struct X11Message
{
    uint length;
    uint type; // Opcode
    ubyte[4096] payload;
}

// Simple X11 Client
struct X11Client
{
    int fd;
    uint windowId;
    uint rootWindow;
    ushort width;
    ushort height;

    void connect()
    {
        // Connect to X11 server via IPC
        // In this OS, we might need a special syscall or open a device
        // For now, assuming we can open a channel or socket
        // TODO: Implement actual connection logic
        // For this stub, we'll just print to stdout
        writeln("[Terminal] Connecting to X11...");
    }

    void createWindow(ushort w, ushort h)
    {
        width = w;
        height = h;
        writeln("[Terminal] Creating window ", w, "x", h);
        // Send CreateWindow request
    }

    void mapWindow()
    {
        writeln("[Terminal] Mapping window");
        // Send MapWindow request
    }

    void drawText(int x, int y, string text)
    {
        // Send drawing commands
        // writeln("[Terminal] Drawing text at ", x, ",", y, ": ", text);
    }
    
    void fillRect(int x, int y, int w, int h, uint color)
    {
        // Send PolyFillRectangle
    }
}

void main(string[] args)
{
    writeln("Starting Terminal Emulator...");

    // 1. Connect to X11
    X11Client x11;
    x11.connect();
    x11.createWindow(800, 600);
    x11.mapWindow();

    // 2. Spawn Shell
    string shellPath = "/bin/zsh";
    if (!exists(shellPath))
    {
        writeln("zsh not found, falling back to /bin/sh");
        shellPath = "/bin/sh";
    }

    // Create pipes
    int[2] stdinPipe;
    int[2] stdoutPipe;
    
    if (pipe(stdinPipe) == -1 || pipe(stdoutPipe) == -1)
    {
        writeln("Failed to create pipes");
        return;
    }

    auto pid = fork();
    if (pid == 0)
    {
        // Child (Shell)
        close(stdinPipe[1]); // Close write end of stdin pipe
        close(stdoutPipe[0]); // Close read end of stdout pipe

        dup2(stdinPipe[0], STDIN_FILENO);
        dup2(stdoutPipe[1], STDOUT_FILENO);
        dup2(stdoutPipe[1], STDERR_FILENO);

        close(stdinPipe[0]);
        close(stdoutPipe[1]);

        // Execute shell
        execl(shellPath.toStringz, shellPath.toStringz, null);
        writeln("Failed to exec shell");
        _exit(1);
    }
    else if (pid > 0)
    {
        // Parent (Terminal)
        close(stdinPipe[0]); // Close read end of stdin pipe
        close(stdoutPipe[1]); // Close write end of stdout pipe

        int shellIn = stdinPipe[1];
        int shellOut = stdoutPipe[0];

        // Event Loop
        ubyte[1024] buffer;
        while (true)
        {
            // Simple polling loop (should use select/poll)
            
            // Read from shell
            auto bytesRead = read(shellOut, buffer.ptr, buffer.length);
            if (bytesRead > 0)
            {
                string output = cast(string)buffer[0..bytesRead];
                write(output); // Echo to console for now
                
                // TODO: Render to X11 window
                x11.drawText(10, 20, output);
            }
            else if (bytesRead == 0)
            {
                writeln("Shell exited");
                break;
            }

            // TODO: Read X11 events (keyboard)
            // For now, just send a command to test
            // write(shellIn, "ls\n".ptr, 3);
            
            // Sleep to avoid busy loop
            // usleep(10000);
        }
        
        int status;
        waitpid(pid, &status, 0);
    }
    else
    {
        writeln("Fork failed");
    }
}
