# VeraCrypt (Stripped Down)

This directory contains a stripped-down version of the VeraCrypt project, focused solely on:
1.  **Full Disk Encryption (FDE)**
2.  **Hidden Operating System (Decoy OS)**

## Directory Structure

*   `src/Boot/Windows`: Contains the MBR bootloader source code. This is the reference implementation for the pre-boot authentication and the Hidden OS switching logic.
    *   `BootMain.cpp`: Core bootloader logic, including `OpenVolume`, `MountVolume`, and hidden volume handling.
*   `src/Crypto`: Core cryptography implementations (AES, Serpent, Twofish, SHA-2, etc.).
*   `src/Format`: Logic for formatting volumes.
*   `src/Volume`: Volume format handling, header parsing, and encryption logic.
*   `src/Common`: Shared utilities and headers.
*   `src/Mount`: Volume mounting logic (OS-specific parts may need adaptation).

## Removed Components

The following components were removed to minimize the footprint:
*   GUI and Main Application logic (`Main`)
*   Windows Drivers (`Driver`)
*   Setup and Installer (`Setup`, `SetupDLL`)
*   COM/ActiveX support (`COMReg`)
*   Smart Card support (`PKCS11`)
*   Resources and Graphics (`Resources`)
*   Code Signing (`Signing`)
*   EFI Binaries (Source is in a separate repo `VeraCrypt-DCS`)
*   Documentation and Tests

## Key Files for Implementation

### Full Disk Encryption
*   `src/Volume/VolumeHeader.cpp`: Parsing and creating volume headers.
*   `src/Crypto`: Encryption algorithms used for disk encryption (XTS mode).

### Decoy OS (Hidden OS)
*   `src/Boot/Windows/BootMain.cpp`:
    *   `OpenVolume`: Handles password entry and determines if the volume is hidden or outer.
    *   `MountVolume`: Mounts the appropriate partition based on the password.
    *   `CopySystemPartitionToHiddenVolume`: Logic for creating the hidden OS.
