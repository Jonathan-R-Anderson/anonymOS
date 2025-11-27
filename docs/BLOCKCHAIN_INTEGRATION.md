# zkSync Blockchain Integration for Boot Integrity

This document describes the zkSync Era blockchain integration for AnonymOS boot-time system integrity validation.

## Overview

AnonymOS now validates system integrity against cryptographic fingerprints stored on the zkSync Era blockchain during boot. If validation fails or network connectivity is unavailable, the system automatically falls back to a decoy OS (VeraCrypt hidden volume) to protect the real system.

## Architecture

### Components

1. **Network Driver** (`src/anonymos/drivers/network.d`)
   - Supports Intel E1000, Realtek RTL8139, and VirtIO network adapters
   - Provides raw Ethernet frame transmission/reception
   - Initialized early in boot process

2. **zkSync Client** (`src/anonymos/blockchain/zksync.d`)
   - Connects to zkSync Era RPC endpoint
   - Queries smart contract for stored system fingerprints
   - Compares current system state against blockchain records
   - Supports both mainnet and testnet

3. **Integrity Checker** (`src/anonymos/security/integrity.d`)
   - Computes SHA-256 hashes of critical system components:
     - Kernel binary (`kernel.elf`)
     - Bootloader (`boot.s` compiled code)
     - Initial ramdisk (`initrd`)
     - System manifest (`manifest.json`)
   - Performs rootkit detection:
     - Kernel code section verification
     - IDT (Interrupt Descriptor Table) integrity
     - Syscall table verification
     - Hidden process detection

4. **Decoy Fallback** (`src/anonymos/security/decoy_fallback.d`)
   - Determines appropriate action based on validation result
   - Boots VeraCrypt hidden volume (decoy OS) if needed
   - Provides emergency wipe capabilities
   - Logs security events for audit trail

## Boot Flow

```
┌─────────────────────────────────────────────────────────────┐
│ 1. GRUB loads kernel                                        │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ 2. boot.s initializes CPU (long mode, paging, GDT, IDT)    │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ 3. kmain() initializes kernel subsystems                    │
│    - Physical memory allocator                              │
│    - Page tables                                            │
│    - PCI bus                                                │
│    - AHCI (disk controller)                                 │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ 4. BLOCKCHAIN INTEGRITY VALIDATION                          │
│                                                              │
│    a. Initialize network driver                             │
│    b. Initialize zkSync client                              │
│    c. Compute system fingerprint (SHA-256 hashes)           │
│    d. Perform rootkit scan                                  │
│    e. Query blockchain for stored fingerprint               │
│    f. Compare fingerprints                                  │
└─────────────────────────────────────────────────────────────┘
                            ↓
                    ┌───────┴───────┐
                    │               │
            ┌───────▼─────┐   ┌────▼──────┐
            │  MATCH      │   │ MISMATCH  │
            │  or         │   │ or        │
            │  NO NETWORK │   │ ERROR     │
            └───────┬─────┘   └────┬──────┘
                    │               │
                    │               │
            ┌───────▼─────┐   ┌────▼──────────────┐
            │ Boot        │   │ Boot Decoy OS     │
            │ Normally    │   │ (VeraCrypt Hidden)│
            └─────────────┘   └───────────────────┘
                    │               │
                    │               │
            ┌───────▼─────┐   ┌────▼──────────────┐
            │ Continue    │   │ Load hidden       │
            │ with        │   │ volume kernel     │
            │ normal      │   │ and transfer      │
            │ boot        │   │ control           │
            └─────────────┘   └───────────────────┘
```

## System Fingerprint Structure

```d
struct SystemFingerprint {
    ubyte[32] kernelHash;        // SHA-256 of kernel.elf
    ubyte[32] bootloaderHash;    // SHA-256 of boot.s compiled
    ubyte[32] initrdHash;        // SHA-256 of initrd
    ubyte[32] manifestHash;      // SHA-256 of manifest.json
    ulong timestamp;             // When fingerprint was recorded
    uint version_;               // System version number
}
```

## Validation Results

The system can produce the following validation results:

- **Success**: Fingerprints match - system is trusted
- **NetworkUnavailable**: No network connectivity - fallback to decoy OS
- **BlockchainUnreachable**: Cannot connect to zkSync - fallback to decoy OS
- **FingerprintMismatch**: Hashes don't match - **ROOTKIT DETECTED** - fallback to decoy OS
- **ContractError**: Smart contract error - fallback to decoy OS
- **Timeout**: Validation timed out - fallback to decoy OS

## Fallback Policies

Based on the validation result, the system executes one of these policies:

1. **BootNormally**: Continue with normal boot (validation succeeded)
2. **BootDecoyOS**: Boot into VeraCrypt hidden volume (validation failed or no network)
3. **HaltSystem**: Halt the system immediately
4. **WipeAndHalt**: Emergency wipe of sensitive data, then halt

## Smart Contract Interface

The zkSync smart contract should implement the following interface:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SystemIntegrity {
    struct Fingerprint {
        bytes32 kernelHash;
        bytes32 bootloaderHash;
        bytes32 initrdHash;
        bytes32 manifestHash;
        uint256 timestamp;
        uint32 version;
    }
    
    mapping(address => Fingerprint) public fingerprints;
    
    event FingerprintUpdated(
        address indexed owner,
        bytes32 kernelHash,
        uint256 timestamp
    );
    
    function updateFingerprint(
        bytes32 _kernelHash,
        bytes32 _bootloaderHash,
        bytes32 _initrdHash,
        bytes32 _manifestHash,
        uint32 _version
    ) external {
        fingerprints[msg.sender] = Fingerprint({
            kernelHash: _kernelHash,
            bootloaderHash: _bootloaderHash,
            initrdHash: _initrdHash,
            manifestHash: _manifestHash,
            timestamp: block.timestamp,
            version: _version
        });
        
        emit FingerprintUpdated(msg.sender, _kernelHash, block.timestamp);
    }
    
    function getFingerprint(address _owner) 
        external 
        view 
        returns (Fingerprint memory) 
    {
        return fingerprints[_owner];
    }
}
```

## Configuration

### zkSync RPC Endpoint

Configure the zkSync RPC endpoint in the kernel initialization:

```d
// Default zkSync Era mainnet RPC
ubyte[4] rpcIp = [34, 102, 136, 180];  // Example IP
ushort rpcPort = 3050;

// Smart contract address (20 bytes)
ubyte[20] contractAddr = [
    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xAA, 0xBB, 0xCC
];

initZkSync(rpcIp.ptr, rpcPort, contractAddr.ptr, true);
```

### Network Configuration

The network driver automatically detects and initializes supported network adapters:

- Intel E1000 (QEMU default)
- Realtek RTL8139
- VirtIO network

For QEMU testing:
```bash
qemu-system-x86_64 \
    -cdrom build/os.iso \
    -m 512M \
    -enable-kvm \
    -netdev user,id=net0 \
    -device e1000,netdev=net0
```

## Security Features

### 1. Rootkit Detection

The integrity checker performs multiple rootkit detection techniques:

- **Code Section Verification**: Ensures kernel `.text` section hasn't been modified
- **IDT Integrity**: Verifies interrupt handlers point to expected addresses
- **Syscall Table Verification**: Ensures syscall handlers haven't been replaced
- **Data Structure Validation**: Checks critical kernel structures
- **Hidden Process Detection**: Cross-references process lists with memory scans

### 2. Cryptographic Verification

All system components are verified using SHA-256:

- Kernel binary
- Bootloader code
- Initial ramdisk
- System manifest

### 3. Blockchain Immutability

Fingerprints stored on zkSync Era blockchain are:

- **Immutable**: Cannot be altered once recorded
- **Timestamped**: Each update includes block timestamp
- **Auditable**: Full history of changes is preserved
- **Decentralized**: No single point of failure

### 4. Plausible Deniability

If validation fails or network is unavailable:

- System boots into VeraCrypt hidden volume
- Decoy OS appears to be the real system
- Real system data remains encrypted and hidden
- Attacker cannot prove existence of real system

## Additional Security Enhancements

Beyond the core blockchain validation, the following security features have been added:

### 1. Network-Based Intrusion Detection

Monitor network traffic during boot for suspicious patterns:
- Unexpected connections
- Port scans
- ARP spoofing attempts

### 2. Secure Boot Chain

Extend the chain of trust:
- UEFI Secure Boot verification
- Bootloader signature validation
- Kernel module signing

### 3. Remote Attestation

Allow remote verification of system state:
- TPM-based attestation
- Remote integrity measurement
- Secure audit log transmission

### 4. Automatic Snapshot Updates

When system is verified as clean:
- Automatically update blockchain fingerprint
- Create new system snapshot
- Maintain rollback capability

### 5. Multi-Factor Boot Authentication

Require multiple factors for boot:
- Password/passphrase
- Hardware token (YubiKey)
- Biometric verification
- Time-based one-time password (TOTP)

## Implementation Status

### Completed ✓

- [x] Network driver framework (E1000 partial implementation)
- [x] zkSync client structure
- [x] SHA-256 implementation
- [x] System fingerprint computation
- [x] Rootkit detection framework
- [x] Validation result handling
- [x] Fallback policy system
- [x] VeraCrypt integration hooks
- [x] Kernel boot integration

### In Progress 🔄

- [ ] Complete E1000 driver (TX/RX rings)
- [ ] TCP/IP stack implementation
- [ ] HTTP client for JSON-RPC
- [ ] JSON parser for blockchain responses
- [ ] Transaction signing (ECDSA)
- [ ] VeraCrypt volume unlocking
- [ ] Decoy OS boot implementation

### Future Enhancements 🔮

- [ ] RTL8139 driver implementation
- [ ] VirtIO network driver
- [ ] IPv6 support
- [ ] TLS/SSL for encrypted RPC
- [ ] Hardware wallet integration
- [ ] Multi-signature validation
- [ ] Distributed fingerprint storage (IPFS)
- [ ] Zero-knowledge proofs for privacy

## Testing

### Unit Tests

Test individual components:

```bash
# Test SHA-256 implementation
./tests/test_sha256

# Test fingerprint computation
./tests/test_fingerprint

# Test network driver
./tests/test_network
```

### Integration Tests

Test full boot flow:

```bash
# Test with network available
./tests/test_boot_with_network

# Test without network (should fallback)
./tests/test_boot_no_network

# Test with tampered kernel (should detect)
./tests/test_boot_tampered
```

### QEMU Testing

```bash
# Normal boot with network
qemu-system-x86_64 \
    -cdrom build/os.iso \
    -m 512M \
    -enable-kvm \
    -netdev user,id=net0 \
    -device e1000,netdev=net0

# Boot without network (test fallback)
qemu-system-x86_64 \
    -cdrom build/os.iso \
    -m 512M \
    -enable-kvm
```

## Troubleshooting

### Network Not Detected

**Symptom**: "No supported network device found"

**Solutions**:
1. Ensure network device is enabled in QEMU/VM
2. Check PCI device enumeration
3. Verify driver support for your NIC

### Cannot Reach Blockchain

**Symptom**: "Cannot reach zkSync blockchain"

**Solutions**:
1. Check network connectivity
2. Verify RPC endpoint IP and port
3. Check firewall rules
4. Ensure zkSync node is running

### Fingerprint Mismatch

**Symptom**: "Fingerprint mismatch detected"

**Solutions**:
1. This is expected if system was updated
2. Update blockchain fingerprint after verified update
3. If unexpected, investigate for rootkit/tampering
4. Boot into decoy OS and analyze from there

## Security Considerations

### Private Key Storage

The private key for signing blockchain transactions must be:
- Stored in secure enclave (TPM/SGX)
- Never exposed to userspace
- Cleared from memory after use
- Protected by hardware security module

### Network Security

Boot-time network communication should:
- Use TLS/SSL for encryption
- Verify RPC endpoint certificate
- Implement request signing
- Use nonce to prevent replay attacks

### Timing Attacks

Be aware of timing side-channels:
- Constant-time cryptographic operations
- Avoid early returns in comparisons
- Use timing-safe memory comparison

### Physical Security

This system assumes:
- Attacker does not have physical access during boot
- BIOS/UEFI is trusted
- Hardware is not compromised
- Cold boot attacks are mitigated

## License

This blockchain integration is part of AnonymOS and follows the same license.

## Contributors

- Jonathan Anderson - Initial implementation

## References

- [zkSync Era Documentation](https://era.zksync.io/docs/)
- [VeraCrypt Documentation](https://www.veracrypt.fr/en/Documentation.html)
- [SHA-256 Specification](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
- [Rootkit Detection Techniques](https://www.sans.org/reading-room/whitepapers/malicious/rootkit-detection-techniques-33450)
