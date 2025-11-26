module anonymos.kernel.usermode;

import anonymos.kernel.pagetable : loadCr3;

@nogc nothrow:

/// Segment selectors for user mode (assuming standard GDT layout)
private enum ushort USER_CS = 0x1B;  // User code segment (RPL=3)
private enum ushort USER_DS = 0x23;  // User data segment (RPL=3)

/// RFLAGS bits
private enum ulong RFLAGS_IF = 1UL << 9;   // Interrupt enable
private enum ulong RFLAGS_RESERVED = 1UL << 1;  // Always 1

/// Enter user mode by executing iretq to transition to ring 3.
/// This function does not return normally - it jumps to user space.
/// 
/// Parameters:
///   entryPoint: User-space instruction pointer (RIP)
///   userStack: User-space stack pointer (RSP)
///   cr3: Page table root for user process
extern(C) void enterUserMode(ulong entryPoint, ulong userStack, ulong cr3)
{
    asm @nogc nothrow
    {
        naked;
        
        // Save parameters from registers (System V ABI: rdi, rsi, rdx)
        mov R8, RDI;   // entryPoint
        mov R9, RSI;   // userStack
        mov R10, RDX;  // cr3
        
        // Load user page table
        mov CR3, R10;

        // Push iretq frame
        mov RAX, USER_DS;
        push RAX;           // SS
        push R9;            // RSP (userStack)
        
        mov RAX, RFLAGS_IF | RFLAGS_RESERVED;
        push RAX;           // RFLAGS
        
        mov RAX, USER_CS;
        push RAX;           // CS
        push R8;            // RIP (entryPoint)
        
        // Zero out general-purpose registers for security
        xor RAX, RAX;
        xor RBX, RBX;
        xor RCX, RCX;
        xor RDX, RDX;
        xor RSI, RSI;
        xor RDI, RDI;
        xor R8, R8;
        xor R9, R9;
        xor R10, R10;
        xor R11, R11;
        xor R12, R12;
        xor R13, R13;
        xor R14, R14;
        xor R15, R15;
        xor RBP, RBP;
        
        // Jump to user mode
        iretq;
    }
}

/// Prepare and enter user mode for a new process.
/// This is typically called after setting up the user process's page tables
/// and loading the executable.
void transitionToUserMode(ulong entryPoint, ulong userStackTop, ulong cr3)
{
    enterUserMode(entryPoint, userStackTop, cr3);
    // Never returns
}
