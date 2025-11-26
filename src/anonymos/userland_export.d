module anonymos.userland_export;

// This module exists solely to export the bootUserland function with C linkage
// The function implementation is here directly to avoid LDC betterC dead code elimination

import anonymos.userland : bootUserland_impl;

export extern(C) @nogc nothrow void minimal_os_bootUserland()
{
    bootUserland_impl();
}
