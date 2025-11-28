module anonymos.display.cursor_diagnostics;

import anonymos.display.framebuffer;
import anonymos.drivers.hid_mouse;
import anonymos.console;

/// Diagnostic data for cursor rendering
struct CursorDiagnostics
{
    // Cursor state tracking
    int lastReportedX;
    int lastReportedY;
    int lastRenderedX;
    int lastRenderedY;
    bool lastVisibleState;
    
    // Frame tracking
    ulong frameCount;
    ulong cursorMoveCount;
    ulong cursorShowCount;
    ulong cursorHideCount;
    ulong cursorForgetCount;
    
    // Performance metrics
    ulong totalMoveDelta;
    ulong maxSingleMoveDelta;
    
    // Error tracking
    ulong jumpDetections;
    ulong flashDetections;
    
    void recordMove(int oldX, int oldY, int newX, int newY) @nogc nothrow
    {
        cursorMoveCount++;
        
        int dx = newX - oldX;
        int dy = newY - oldY;
        if (dx < 0) dx = -dx;
        if (dy < 0) dy = -dy;
        
        ulong delta = cast(ulong)(dx + dy);
        totalMoveDelta += delta;
        
        if (delta > maxSingleMoveDelta)
        {
            maxSingleMoveDelta = delta;
        }
        
        // Detect jumps (movement > 100 pixels in one frame)
        if (delta > 100)
        {
            jumpDetections++;
            print("[cursor-diag] JUMP detected: (");
            printUnsigned(cast(uint)oldX);
            print(", ");
            printUnsigned(cast(uint)oldY);
            print(") -> (");
            printUnsigned(cast(uint)newX);
            print(", ");
            printUnsigned(cast(uint)newY);
            print(") delta=");
            printUnsigned(cast(uint)delta);
            printLine("");
        }
        
        lastReportedX = newX;
        lastReportedY = newY;
    }
    
    void recordShow() @nogc nothrow
    {
        cursorShowCount++;
        lastVisibleState = true;
    }
    
    void recordHide() @nogc nothrow
    {
        cursorHideCount++;
        lastVisibleState = false;
    }
    
    void recordForget() @nogc nothrow
    {
        cursorForgetCount++;
        lastVisibleState = false;
    }
    
    void recordFrame() @nogc nothrow
    {
        frameCount++;
        
        // Detect flashing (show/hide more than once per frame on average)
        if (frameCount > 0 && (cursorShowCount + cursorHideCount) > frameCount * 2)
        {
            flashDetections++;
            if (flashDetections % 100 == 1)
            {
                printLine("[cursor-diag] FLASH detected: excessive show/hide calls");
            }
        }
    }
    
    void printReport() @nogc nothrow
    {
        printLine("=== Cursor Diagnostics Report ===");
        
        print("Frames rendered: ");
        printUnsigned(cast(uint)frameCount);
        printLine("");
        
        print("Cursor moves: ");
        printUnsigned(cast(uint)cursorMoveCount);
        printLine("");
        
        print("Cursor shows: ");
        printUnsigned(cast(uint)cursorShowCount);
        printLine("");
        
        print("Cursor hides: ");
        printUnsigned(cast(uint)cursorHideCount);
        printLine("");
        
        print("Cursor forgets: ");
        printUnsigned(cast(uint)cursorForgetCount);
        printLine("");
        
        if (cursorMoveCount > 0)
        {
            print("Average move delta: ");
            printUnsigned(cast(uint)(totalMoveDelta / cursorMoveCount));
            printLine("");
        }
        
        print("Max single move delta: ");
        printUnsigned(cast(uint)maxSingleMoveDelta);
        printLine("");
        
        print("Jump detections: ");
        printUnsigned(cast(uint)jumpDetections);
        printLine("");
        
        print("Flash detections: ");
        printUnsigned(cast(uint)flashDetections);
        printLine("");
        
        print("Last position: (");
        printUnsigned(cast(uint)lastReportedX);
        print(", ");
        printUnsigned(cast(uint)lastReportedY);
        printLine(")");
        
        print("Cursor visible: ");
        printLine(lastVisibleState ? "yes" : "no");
    }
}

__gshared CursorDiagnostics g_cursorDiag;

/// Wrapper for framebufferMoveCursor with diagnostics
void framebufferMoveCursorDiag(int x, int y) @nogc nothrow
{
    int oldX, oldY;
    getMousePosition(oldX, oldY);
    
    g_cursorDiag.recordMove(oldX, oldY, x, y);
    framebufferMoveCursor(x, y);
}

/// Wrapper for framebufferShowCursor with diagnostics
void framebufferShowCursorDiag() @nogc nothrow
{
    g_cursorDiag.recordShow();
    framebufferShowCursor();
}

/// Wrapper for framebufferHideCursor with diagnostics
void framebufferHideCursorDiag() @nogc nothrow
{
    g_cursorDiag.recordHide();
    framebufferHideCursor();
}

/// Wrapper for framebufferForgetCursor with diagnostics
void framebufferForgetCursorDiag() @nogc nothrow
{
    g_cursorDiag.recordForget();
    framebufferForgetCursor();
}

/// Call at end of each frame
void recordFrameDiag() @nogc nothrow
{
    g_cursorDiag.recordFrame();
}

/// Print diagnostic report
extern(C) void printCursorDiagnostics() @nogc nothrow
{
    g_cursorDiag.printReport();
}
