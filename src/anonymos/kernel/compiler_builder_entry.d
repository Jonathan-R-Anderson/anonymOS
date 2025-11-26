module anonymos.kernel.compiler_builder_entry;

pragma(mangle, "compilerBuilderProcessEntry")
export extern(C) @nogc nothrow void compilerBuilderProcessEntry(const(char*)* argv, const(char*)* envp)
{
    // Minimal stub to satisfy linker; no operation.
}
