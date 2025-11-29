---
description: Debugging the Double Fault in AnonymOS Kernel
---

# Debugging Double Fault in AnonymOS Kernel

## Problem Description
The system crashes with a "Double Fault" during the execution of the desktop process. The crash occurs inside the `schedYield` function during context switching.

## Investigation Findings

1.  **Crash Location**: The crash happens when `arch_context_switch` attempts to jump to the restored `RIP`.
2.  **RIP Corruption**: The `RIP` value in `proc.context.regs[7]` is corrupted.
    *   Expected: Address of `Lresume` label inside `setjmp` (e.g., `0x13AD65`).
    *   Actual: A different code address (e.g., `0x13AEB5`), which points to `findUtilityIndex`.
3.  **Timing**: The corruption happens *after* `saveProcessContext` returns (where `RIP` is correct) and *before* `arch_context_switch` reads it.
4.  **Isolation**:
    *   Disabling `schedYield` in `runSimpleDesktopLoop` prevents the crash.
    *   Increasing stack size or using a static stack for PID 3 did not resolve the issue.
    *   Marking functions `extern(C)` did not resolve the issue.

## Hypothesis
The `Proc` structure (specifically `proc.context`) is being overwritten by a stack frame or other memory corruption. The presence of a valid code address (`0x13AEB5`) in `RIP` suggests that a return address from the stack might have been copied into `proc.context`.

## Next Steps
1.  **Memory Watchpoint**: If possible, set a watchpoint on `proc.context.regs[7]` to see who writes to it.
2.  **Audit Memory Ops**: Check for `memcpy` or pointer arithmetic that might affect `g_ptable`.
3.  **Verify `g_current`**: Ensure `g_current` always points to `g_ptable` and not a stack copy.
