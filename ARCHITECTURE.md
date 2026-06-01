# Kernel Architecture

* Kernel written primarily in Haskell + D
* x86_64 target
* Limine bootloader
* ELF userspace loading supported
* Linux compatibility layer exists
* Userspace entry through enterLinuxAddressSpaceSc
* Context switching through x64SwitchTasks
* Paging handled through archMapPage
* Fault handling through handleFaultAt

## Constraints

Avoid:

* dynamic logging
* generic Word64 Storable instances
* show/showHex
* ++

Prefer:

* minimal diffs
* architecture-preserving fixes
* explicit ABI correctness
* SysV-compliant userspace entry

## Current Known Issues

* userspace ELF faults after returning from _start
* possible stack alignment issue
* possible saved RIP restoration issue
