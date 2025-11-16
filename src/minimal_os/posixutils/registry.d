module minimal_os.posixutils.registry;

alias ExecEntryFn = extern(C) @nogc nothrow
    void function(const(char*)* argv, const(char*)* envp);

@nogc nothrow ExecEntryFn posixUtilityExecEntry(scope const(char)[] /*name*/)
{
    return null;
}

@nogc nothrow bool embeddedPosixUtilitiesAvailable()
{
    return false;
}

@nogc nothrow string[] embeddedPosixUtilityPaths()
{
    return [];
}
