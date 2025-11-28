module tests.cursor_movement_test;

import anonymos.drivers.hid_mouse;
import anonymos.display.input_pipeline;
import anonymos.display.framebuffer;

/// Test harness for cursor movement validation
struct CursorTestHarness
{
    uint screenWidth;
    uint screenHeight;
    int expectedX;
    int expectedY;
    ubyte expectedButtons;
    
    // Track all events generated
    InputEvent[100] events;
    size_t eventCount;
    
    // Simulated input queue
    InputQueue testQueue;
    
    void initialize(uint width, uint height) @nogc nothrow
    {
        screenWidth = width;
        screenHeight = height;
        eventCount = 0;
        testQueue = InputQueue.init;
        
        // Initialize mouse state
        initializeMouseState(width, height);
        
        // Get initial position (should be center)
        getMousePosition(expectedX, expectedY);
    }
    
    void recordEvent(ref const InputEvent event) @nogc nothrow
    {
        if (eventCount < events.length)
        {
            events[eventCount++] = event;
        }
    }
    
    void simulateMouseReport(byte deltaX, byte deltaY, ubyte buttons) @nogc nothrow
    {
        HIDMouseReport report;
        report.deltaX = deltaX;
        report.deltaY = deltaY;
        report.buttons = buttons;
        report.deltaWheel = 0;
        
        // Clear event queue
        testQueue.head = 0;
        testQueue.tail = 0;
        
        // Process the report
        processMouseReport(report, testQueue, screenWidth, screenHeight);
        
        // Record all generated events
        size_t idx = testQueue.head;
        while (idx != testQueue.tail)
        {
            recordEvent(testQueue.events[idx]);
            idx = (idx + 1) % testQueue.capacity;
        }
        
        // Update expected position
        expectedX += deltaX;
        expectedY += deltaY;
        
        // Clamp to screen bounds
        if (expectedX < 0) expectedX = 0;
        if (expectedY < 0) expectedY = 0;
        if (expectedX >= screenWidth) expectedX = cast(int)screenWidth - 1;
        if (expectedY >= screenHeight) expectedY = cast(int)screenHeight - 1;
        
        expectedButtons = buttons;
    }
    
    bool validatePosition() @nogc nothrow
    {
        int actualX, actualY;
        getMousePosition(actualX, actualY);
        
        return actualX == expectedX && actualY == expectedY;
    }
    
    bool validateLastEvent(InputEvent.Type expectedType, int expectedData1, int expectedData2, ubyte expectedData3) @nogc nothrow
    {
        if (eventCount == 0) return false;
        
        auto lastEvent = events[eventCount - 1];
        return lastEvent.type == expectedType &&
               lastEvent.data1 == expectedData1 &&
               lastEvent.data2 == expectedData2 &&
               lastEvent.data3 == expectedData3;
    }
    
    void printDiagnostics() @nogc nothrow
    {
        import anonymos.console : print, printLine, printUnsigned;
        
        print("[test] Expected position: (");
        printUnsigned(cast(uint)expectedX);
        print(", ");
        printUnsigned(cast(uint)expectedY);
        printLine(")");
        
        int actualX, actualY;
        getMousePosition(actualX, actualY);
        print("[test] Actual position: (");
        printUnsigned(cast(uint)actualX);
        print(", ");
        printUnsigned(cast(uint)actualY);
        printLine(")");
        
        print("[test] Events generated: ");
        printUnsigned(cast(uint)eventCount);
        printLine("");
    }
}

/// Test: Basic movement in all directions
bool testBasicMovement() @nogc nothrow
{
    import anonymos.console : printLine;
    
    CursorTestHarness harness;
    harness.initialize(1024, 768);
    
    printLine("[test] Testing basic movement...");
    
    // Move right
    harness.simulateMouseReport(10, 0, 0);
    if (!harness.validatePosition())
    {
        printLine("[FAIL] Move right failed");
        harness.printDiagnostics();
        return false;
    }
    
    // Move left
    harness.simulateMouseReport(-10, 0, 0);
    if (!harness.validatePosition())
    {
        printLine("[FAIL] Move left failed");
        harness.printDiagnostics();
        return false;
    }
    
    // Move down
    harness.simulateMouseReport(0, 10, 0);
    if (!harness.validatePosition())
    {
        printLine("[FAIL] Move down failed");
        harness.printDiagnostics();
        return false;
    }
    
    // Move up
    harness.simulateMouseReport(0, -10, 0);
    if (!harness.validatePosition())
    {
        printLine("[FAIL] Move up failed");
        harness.printDiagnostics();
        return false;
    }
    
    printLine("[PASS] Basic movement test");
    return true;
}

/// Test: Boundary clamping
bool testBoundaryClamping() @nogc nothrow
{
    import anonymos.console : printLine, printUnsigned;
    
    CursorTestHarness harness;
    harness.initialize(1024, 768);
    
    printLine("[test] Testing boundary clamping...");
    
    // Move far right (should clamp)
    harness.simulateMouseReport(127, 0, 0);
    harness.simulateMouseReport(127, 0, 0);
    harness.simulateMouseReport(127, 0, 0);
    harness.simulateMouseReport(127, 0, 0);
    harness.simulateMouseReport(127, 0, 0);
    
    int x, y;
    getMousePosition(x, y);
    if (x != 1023)
    {
        printLine("[FAIL] Right boundary clamping failed");
        harness.printDiagnostics();
        return false;
    }
    
    // Move far left (should clamp)
    harness.simulateMouseReport(-127, 0, 0);
    harness.simulateMouseReport(-127, 0, 0);
    harness.simulateMouseReport(-127, 0, 0);
    harness.simulateMouseReport(-127, 0, 0);
    harness.simulateMouseReport(-127, 0, 0);
    
    getMousePosition(x, y);
    if (x != 0)
    {
        printLine("[FAIL] Left boundary clamping failed");
        harness.printDiagnostics();
        return false;
    }
    
    printLine("[PASS] Boundary clamping test");
    return true;
}

/// Test: Button press/release detection
bool testButtonDetection() @nogc nothrow
{
    import anonymos.console : printLine;
    
    CursorTestHarness harness;
    harness.initialize(1024, 768);
    
    printLine("[test] Testing button detection...");
    
    // Press left button
    harness.simulateMouseReport(0, 0, 0x01);
    if (harness.eventCount == 0)
    {
        printLine("[FAIL] No event generated for button press");
        return false;
    }
    
    bool foundButtonDown = false;
    foreach (i; 0 .. harness.eventCount)
    {
        if (harness.events[i].type == InputEvent.Type.buttonDown &&
            harness.events[i].data3 == 0x01)
        {
            foundButtonDown = true;
            break;
        }
    }
    
    if (!foundButtonDown)
    {
        printLine("[FAIL] buttonDown event not found");
        return false;
    }
    
    // Release left button
    harness.simulateMouseReport(0, 0, 0x00);
    
    bool foundButtonUp = false;
    foreach (i; 0 .. harness.eventCount)
    {
        if (harness.events[i].type == InputEvent.Type.buttonUp &&
            harness.events[i].data3 == 0x01)
        {
            foundButtonUp = true;
            break;
        }
    }
    
    if (!foundButtonUp)
    {
        printLine("[FAIL] buttonUp event not found");
        return false;
    }
    
    printLine("[PASS] Button detection test");
    return true;
}

/// Test: Rapid movement (stress test)
bool testRapidMovement() @nogc nothrow
{
    import anonymos.console : printLine, printUnsigned, print;
    
    CursorTestHarness harness;
    harness.initialize(1024, 768);
    
    printLine("[test] Testing rapid movement...");
    
    // Simulate 100 rapid movements
    foreach (i; 0 .. 100)
    {
        byte dx = cast(byte)((i % 10) - 5);
        byte dy = cast(byte)((i % 7) - 3);
        harness.simulateMouseReport(dx, dy, 0);
        
        if (!harness.validatePosition())
        {
            print("[FAIL] Rapid movement failed at iteration ");
            printUnsigned(cast(uint)i);
            printLine("");
            harness.printDiagnostics();
            return false;
        }
    }
    
    printLine("[PASS] Rapid movement test");
    return true;
}

/// Test: Zero-delta reports (should not generate move events)
bool testZeroDelta() @nogc nothrow
{
    import anonymos.console : printLine;
    
    CursorTestHarness harness;
    harness.initialize(1024, 768);
    
    printLine("[test] Testing zero-delta reports...");
    
    // Send zero-delta report
    harness.simulateMouseReport(0, 0, 0);
    
    // Should not generate any pointer move events
    foreach (i; 0 .. harness.eventCount)
    {
        if (harness.events[i].type == InputEvent.Type.pointerMove)
        {
            printLine("[FAIL] Zero-delta generated move event");
            return false;
        }
    }
    
    printLine("[PASS] Zero-delta test");
    return true;
}

/// Test: Diagonal movement
bool testDiagonalMovement() @nogc nothrow
{
    import anonymos.console : printLine;
    
    CursorTestHarness harness;
    harness.initialize(1024, 768);
    
    printLine("[test] Testing diagonal movement...");
    
    // Move diagonally (down-right)
    harness.simulateMouseReport(10, 10, 0);
    if (!harness.validatePosition())
    {
        printLine("[FAIL] Diagonal movement failed");
        harness.printDiagnostics();
        return false;
    }
    
    // Move diagonally (up-left)
    harness.simulateMouseReport(-10, -10, 0);
    if (!harness.validatePosition())
    {
        printLine("[FAIL] Reverse diagonal movement failed");
        harness.printDiagnostics();
        return false;
    }
    
    printLine("[PASS] Diagonal movement test");
    return true;
}

/// Run all cursor tests
extern(C) void runCursorTests() @nogc nothrow
{
    import anonymos.console : printLine;
    
    printLine("=== Cursor Movement Test Suite ===");
    
    uint passed = 0;
    uint failed = 0;
    
    if (testBasicMovement()) passed++; else failed++;
    if (testBoundaryClamping()) passed++; else failed++;
    if (testButtonDetection()) passed++; else failed++;
    if (testRapidMovement()) passed++; else failed++;
    if (testZeroDelta()) passed++; else failed++;
    if (testDiagonalMovement()) passed++; else failed++;
    
    printLine("=== Test Results ===");
    import anonymos.console : print, printUnsigned;
    print("Passed: "); printUnsigned(passed); printLine("");
    print("Failed: "); printUnsigned(failed); printLine("");
}
