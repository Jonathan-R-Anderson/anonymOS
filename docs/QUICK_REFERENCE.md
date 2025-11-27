# Quick Reference: Blockchain Integration

## Boot Flow

```
Hardware Init → Network Init → Blockchain Validation → Fallback Decision → Continue/Decoy
```

## Key Components

| Component | File | Purpose |
|-----------|------|---------|
| Network Driver | `drivers/network.d` | Ethernet connectivity |
| zkSync Client | `blockchain/zksync.d` | Blockchain communication |
| Integrity Checker | `security/integrity.d` | SHA-256, fingerprinting |
| Fallback System | `security/decoy_fallback.d` | Policy execution |
| VeraCrypt | `drivers/veracrypt.d` | Decoy OS boot |

## API Reference

### Network Driver

```d
// Initialize network
void initNetwork();

// Check availability
bool isNetworkAvailable();

// Send/receive Ethernet frames
bool sendEthFrame(const(ubyte)* data, size_t len);
int receiveEthFrame(ubyte* buffer, size_t maxLen);

// Get MAC address
void getMacAddress(ubyte* outMac);
```

### zkSync Client

```d
// Initialize client
void initZkSync(const(ubyte)* rpcIp, ushort rpcPort, 
                const(ubyte)* contractAddr, bool mainnet);

// Validate system integrity
ValidationResult validateSystemIntegrity(const SystemFingerprint* current);

// Store fingerprint on blockchain
bool storeSystemFingerprint(const SystemFingerprint* fingerprint);
```

### Integrity Checker

```d
// Compute SHA-256 hash
void sha256(const(ubyte)* data, size_t len, ubyte* outHash);

// Compute system fingerprint
void computeSystemFingerprint(SystemFingerprint* outFingerprint);

// Check for rootkits
bool checkForRootkits();

// Perform boot integrity check
ValidationResult performBootIntegrityCheck();
```

### Fallback System

```d
// Determine fallback action
FallbackPolicy determineFallbackAction(ValidationResult validationResult);

// Execute fallback
void executeFallback(FallbackPolicy policy);

// Display security warning
void displaySecurityWarning(ValidationResult result);

// Log security event
void logSecurityEvent(ValidationResult result, FallbackPolicy policy);
```

### VeraCrypt

```d
// Check if VeraCrypt is available
bool isVeraCryptAvailable();

// Boot into decoy OS
bool bootDecoyOS();

// Prompt for password
bool promptForPassword(char* buffer, size_t maxLen);

// Unlock volume
bool unlockVolume(const(char)* password, BootType* outType);
```

## Data Structures

### SystemFingerprint

```d
struct SystemFingerprint {
    ubyte[32] kernelHash;        // SHA-256 of kernel.elf
    ubyte[32] bootloaderHash;    // SHA-256 of boot.s
    ubyte[32] initrdHash;        // SHA-256 of initrd
    ubyte[32] manifestHash;      // SHA-256 of manifest.json
    ulong timestamp;             // Timestamp
    uint version_;               // Version number
}
```

### ValidationResult

```d
enum ValidationResult {
    Success,                     // ✅ Validation succeeded
    NetworkUnavailable,          // ⚠️ No network
    BlockchainUnreachable,       // ⚠️ Cannot reach blockchain
    FingerprintMismatch,         // ❌ ROOTKIT DETECTED
    ContractError,               // ⚠️ Contract error
    Timeout,                     // ⚠️ Timeout
}
```

### FallbackPolicy

```d
enum FallbackPolicy {
    BootNormally,               // Continue normal boot
    BootDecoyOS,                // Boot into decoy OS
    HaltSystem,                 // Halt immediately
    WipeAndHalt,                // Wipe then halt
}
```

## Configuration

### zkSync RPC Endpoint

```d
// In src/anonymos/kernel/kernel.d
ubyte[4] rpcIp = [34, 102, 136, 180];  // RPC IP address
ushort rpcPort = 3050;                  // RPC port

ubyte[20] contractAddr = [              // Contract address
    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xAA, 0xBB, 0xCC
];

initZkSync(rpcIp.ptr, rpcPort, contractAddr.ptr, true);
```

### Network Device

```d
// Automatically detected via PCI scan
// Supported devices:
// - Intel E1000 (0x8086:0x100E)
// - Realtek RTL8139 (0x10EC:0x8139)
// - VirtIO Network (0x1AF4:0x1000)
```

## Smart Contract Interface

### Update Fingerprint

```solidity
function updateFingerprint(
    bytes32 _kernelHash,
    bytes32 _bootloaderHash,
    bytes32 _initrdHash,
    bytes32 _manifestHash,
    uint32 _version,
    string calldata _reason
) external;
```

### Get Fingerprint

```solidity
function getFingerprint(address _owner) 
    external 
    view 
    returns (Fingerprint memory);
```

### Verify Fingerprint

```solidity
function verifyFingerprint(
    address _owner,
    bytes32 _kernelHash,
    bytes32 _bootloaderHash,
    bytes32 _initrdHash,
    bytes32 _manifestHash
) external view returns (bool);
```

## Testing

### QEMU with Network

```bash
qemu-system-x86_64 \
    -cdrom build/os.iso \
    -m 512M \
    -enable-kvm \
    -netdev user,id=net0 \
    -device e1000,netdev=net0
```

### QEMU without Network

```bash
qemu-system-x86_64 \
    -cdrom build/os.iso \
    -m 512M \
    -enable-kvm
```

## Debugging

### Enable Verbose Logging

Add to kernel initialization:

```d
// Enable network debug output
g_networkDebug = true;

// Enable zkSync debug output
g_zkSyncDebug = true;

// Enable integrity debug output
g_integrityDebug = true;
```

### Check Network Status

```d
if (!isNetworkAvailable()) {
    printLine("[debug] Network not available");
    printLine("[debug] Check PCI device enumeration");
    printLine("[debug] Verify network adapter is enabled");
}
```

### Check Blockchain Connection

```d
if (!connectToZkSync()) {
    printLine("[debug] Cannot connect to zkSync");
    printLine("[debug] Check RPC endpoint configuration");
    printLine("[debug] Verify network connectivity");
    printLine("[debug] Check firewall rules");
}
```

### Verify Fingerprint Computation

```d
SystemFingerprint fp;
computeSystemFingerprint(&fp);

printLine("[debug] Kernel hash:");
printHex(fp.kernelHash.ptr, 32);

printLine("[debug] Bootloader hash:");
printHex(fp.bootloaderHash.ptr, 32);
```

## Common Issues

### "No supported network device found"

**Cause**: Network adapter not detected or unsupported

**Solution**:
1. Check QEMU network device configuration
2. Verify PCI enumeration is working
3. Add support for your network adapter

### "Cannot reach zkSync blockchain"

**Cause**: Network connectivity or RPC endpoint issue

**Solution**:
1. Verify network is initialized
2. Check RPC endpoint IP and port
3. Test connectivity with `ping` or `curl`
4. Verify zkSync node is running

### "Fingerprint mismatch detected"

**Cause**: System files have been modified

**Solution**:
1. If expected (after update): Update blockchain fingerprint
2. If unexpected: Investigate for rootkit/tampering
3. System will boot into decoy OS for safety

### "VeraCrypt not available"

**Cause**: VeraCrypt bootloader not installed

**Solution**:
1. Run installer to set up VeraCrypt
2. Configure hidden volume
3. Verify bootloader is installed

## Performance

### Boot Time Impact

| Phase | Time | Notes |
|-------|------|-------|
| Network Init | ~100ms | PCI scan + driver init |
| Fingerprint Compute | ~50ms | SHA-256 of ~10MB |
| Blockchain Query | ~500ms | Network latency |
| Rootkit Scan | ~100ms | Multiple checks |
| **Total** | **~750ms** | Acceptable overhead |

### Network Bandwidth

| Operation | Size | Notes |
|-----------|------|-------|
| Query Fingerprint | ~2KB | JSON-RPC request |
| Response | ~1KB | Fingerprint data |
| Update Fingerprint | ~3KB | Transaction data |
| **Total** | **~6KB** | Minimal bandwidth |

## Security Checklist

- [ ] Smart contract deployed to zkSync Era
- [ ] Contract address configured in kernel
- [ ] Network driver initialized
- [ ] SHA-256 implementation tested
- [ ] Fingerprint computation verified
- [ ] Rootkit detection enabled
- [ ] Fallback policy configured
- [ ] VeraCrypt hidden volume set up
- [ ] Decoy OS tested
- [ ] Audit logging enabled

## Resources

- **Documentation**: `docs/BLOCKCHAIN_INTEGRATION.md`
- **Smart Contract**: `contracts/SystemIntegrity.sol`
- **Deployment Guide**: `contracts/README.md`
- **Implementation Summary**: `docs/IMPLEMENTATION_SUMMARY.md`
- **Main README**: `README.md` (section 8)

## Support

For issues or questions:

1. Check documentation in `docs/`
2. Review implementation in `src/anonymos/`
3. Test with QEMU
4. Check logs for error messages
5. Verify configuration

---

**Quick Start**: See `docs/BLOCKCHAIN_INTEGRATION.md` for detailed setup instructions.
