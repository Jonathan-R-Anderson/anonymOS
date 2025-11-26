#!/usr/bin/env python3
"""
Fix remaining posix references in the mixin template.
"""
import re

filepath = '/home/jonny/Documents/internetcomputer/src/anonymos/syscalls/posix.d'

with open(filepath, 'r', encoding='utf-8') as f:
    content = f.read()

# Replace all references to anonymos.posix with anonymos.syscalls.posix
# but be careful not to replace the module declaration itself
content = re.sub(r'(\s+)alias ProcessEntry = anonymos\.posix\.', r'\1alias ProcessEntry = anonymos.syscalls.posix.', content)
content = re.sub(r'(\s+)alias PosixUtilityExecEntryFn = anonymos\.posix\.', r'\1alias PosixUtilityExecEntryFn = anonymos.syscalls.posix.', content)
content = re.sub(r'(\s+)alias EmbeddedPosixUtilitiesAvailableFn =\s+anonymos\.posix\.', r'\1alias EmbeddedPosixUtilitiesAvailableFn =\n        anonymos.syscalls.posix.', content)
content = re.sub(r'(\s+)alias EmbeddedPosixUtilityPathsFn =\s+anonymos\.posix\.', r'\1alias EmbeddedPosixUtilityPathsFn =\n        anonymos.syscalls.posix.', content)
content = re.sub(r'(\s+)alias RegistryEmbeddedPosixUtilitiesAvailableFn =\s+anonymos\.posix\.', r'\1alias RegistryEmbeddedPosixUtilitiesAvailableFn =\n        anonymos.syscalls.posix.', content)
content = re.sub(r'(\s+)alias RegistryEmbeddedPosixUtilityPathsFn =\s+anonymos\.posix\.', r'\1alias RegistryEmbeddedPosixUtilityPathsFn =\n        anonymos.syscalls.posix.', content)
content = re.sub(r'(\s+)alias g_shellRegistered = anonymos\.posix\.', r'\1alias g_shellRegistered = anonymos.syscalls.posix.', content)
content = re.sub(r'(\s+)alias g_shellDefaultArgv = anonymos\.posix\.', r'\1alias g_shellDefaultArgv = anonymos.syscalls.posix.', content)
content = re.sub(r'(\s+)alias g_shellDefaultEnvp = anonymos\.posix\.', r'\1alias g_shellDefaultEnvp = anonymos.syscalls.posix.', content)
content = re.sub(r'(\s+)alias SHELL_PATH = anonymos\.posix\.', r'\1alias SHELL_PATH = anonymos.syscalls.posix.', content)
content = re.sub(r'(\s+)alias ensureBareMetalShellInterfaces =\s+anonymos\.posix\.', r'\1alias ensureBareMetalShellInterfaces =\n        anonymos.syscalls.posix.', content)
content = re.sub(r'(\s+)alias ENABLE_POSIX_DEBUG\s+=\s+anonymos\.posix\.', r'\1alias ENABLE_POSIX_DEBUG      = anonymos.syscalls.posix.', content)
content = re.sub(r'(\s+)alias debugPrefix\s+=\s+anonymos\.posix\.', r'\1alias debugPrefix             = anonymos.syscalls.posix.', content)
content = re.sub(r'(\s+)alias debugBool\s+=\s+anonymos\.posix\.', r'\1alias debugBool               = anonymos.syscalls.posix.', content)
content = re.sub(r'(\s+)alias debugExpectActual\s+=\s+anonymos\.posix\.', r'\1alias debugExpectActual       = anonymos.syscalls.posix.', content)
content = re.sub(r'(\s+)alias debugLog\s+=\s+anonymos\.posix\.', r'\1alias debugLog                = anonymos.syscalls.posix.', content)
content = re.sub(r'(\s+)alias probeKernelConsoleReady = anonymos\.posix\.', r'\1alias probeKernelConsoleReady = anonymos.syscalls.posix.', content)
content = re.sub(r'(\s+)alias probeSerialConsoleReady = anonymos\.posix\.', r'\1alias probeSerialConsoleReady = anonymos.syscalls.posix.', content)
content = re.sub(r'(\s+)alias cStringLength\s+=\s+anonymos\.posix\.', r'\1alias cStringLength           = anonymos.syscalls.posix.', content)
content = re.sub(r'(\s+)alias cStringEquals\s+=\s+anonymos\.posix\.', r'\1alias cStringEquals           = anonymos.syscalls.posix.', content)
content = re.sub(r'(\s+)alias jmp_buf = anonymos\.posix\.', r'\1alias jmp_buf = anonymos.syscalls.posix.', content)
content = re.sub(r'(\s+)alias setjmp\s+=\s+anonymos\.posix\.', r'\1alias setjmp  = anonymos.syscalls.posix.', content)
content = re.sub(r'(\s+)alias longjmp = anonymos\.posix\.', r'\1alias longjmp = anonymos.syscalls.posix.', content)

with open(filepath, 'w', encoding='utf-8') as f:
    f.write(content)

print("Fixed posix references in mixin template")
