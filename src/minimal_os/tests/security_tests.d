module minimal_os.tests.security_tests;

import minimal_os.objects;
import minimal_os.console : printLine, print;

// Test 1: Cycle Prevention
@nogc nothrow bool testCyclePrevention()
{
    // Create directories
    auto dir1 = createDirectory();
    auto dir2 = createDirectory();
    auto dir3 = createDirectory();
    
    // Create chain: dir1 -> dir2 -> dir3
    auto cap2 = Capability(dir2, Rights.Read | Rights.Write | Rights.Enumerate);
    auto cap3 = Capability(dir3, Rights.Read | Rights.Write | Rights.Enumerate);
    
    addEntry(dir1, "subdir", cap2);
    addEntry(dir2, "deeper", cap3);
    
    // Try to create cycle: dir3 -> dir1 (should fail)
    auto cap1 = Capability(dir1, Rights.Read | Rights.Write | Rights.Enumerate);
    bool result = addEntry(dir3, "cycle", cap1);
    
    return !result; // Should return false (cycle prevented)
}

// Test 2: Rights Attenuation
@nogc nothrow bool testRightsAttenuation()
{
    auto parentDir = createDirectory();
    auto childDir = createDirectory();
    
    // Parent has limited rights
    // Simulate by setting g_rootObject to parentDir temporarily
    auto oldRoot = g_rootObject;
    g_rootObject = parentDir;
    
    // Try to add child with MORE rights than parent
    auto childCap = Capability(
        childDir, 
        Rights.Read | Rights.Write | Rights.Execute | Rights.Grant | Rights.Enumerate | Rights.Call
    );
    
    addEntry(parentDir, "child", childCap);
    
    // Lookup the child and check if rights were attenuated
    auto resultCap = lookup(parentDir, "child");
    
    // Restore root
    g_rootObject = oldRoot;
    
    // Rights should be attenuated to parent's level
    uint parentRights = Rights.Read | Rights.Write | Rights.Enumerate;
    return (resultCap.rights & ~parentRights) == 0;
}

// Test 3: Self-Reference Prevention
@nogc nothrow bool testSelfReference()
{
    auto dir = createDirectory();
    auto selfCap = Capability(dir, Rights.Read | Rights.Enumerate);
    
    // Try to add directory to itself (should fail)
    bool result = addEntry(dir, "self", selfCap);
    
    return !result; // Should return false (self-reference prevented)
}

// Test 4: Search with Permissions
@nogc nothrow bool testPermissionAwareSearch()
{
    auto root = createDirectory();
    auto dir1 = createDirectory();
    auto blob1 = createBlob(cast(const(ubyte)[])"test data");
    
    // Add with limited rights
    auto dirCap = Capability(dir1, Rights.Read); // No Enumerate!
    auto blobCap = Capability(blob1, Rights.Read | Rights.Execute);
    
    addEntry(root, "dir1", dirCap);
    addEntry(dir1, "file", blobCap);
    
    // Search for executables
    SearchResult[10] results;
    size_t count = searchTree(root, &isExecutable, results.ptr, 10);
    
    // Should find 0 because dir1 doesn't have Enumerate right
    return count == 0;
}

// Run all tests
export extern(C) void runSecurityTests()
{
    printLine("=== Object Capability Security Tests ===");
    
    print("Test 1: Cycle Prevention... ");
    if (testCyclePrevention())
        printLine("PASS");
    else
        printLine("FAIL");
    
    print("Test 2: Rights Attenuation... ");
    if (testRightsAttenuation())
        printLine("PASS");
    else
        printLine("FAIL");
    
    print("Test 3: Self-Reference Prevention... ");
    if (testSelfReference())
        printLine("PASS");
    else
        printLine("FAIL");
    
    print("Test 4: Permission-Aware Search... ");
    if (testPermissionAwareSearch())
        printLine("PASS");
    else
        printLine("FAIL");
    
    printLine("=== Tests Complete ===");
}
