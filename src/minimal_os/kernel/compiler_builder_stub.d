module minimal_os.kernel.compiler_builder_stub;

import minimal_os.console : printLine;

// Provide a weak fallback for the compiler builder entry point so the kernel
// still links when the full userland is not present. When the real
// implementation is linked (from shell_integration.d), the strong symbol
// overrides this stub.
pragma(weak, compilerBuilderProcessEntry);
extern(C) @nogc nothrow void compilerBuilderProcessEntry(const(char*)* /*argv*/, const(char*)* /*envp*/)
{
    printLine("[kernel] compiler builder unavailable; stub entry used");
}
