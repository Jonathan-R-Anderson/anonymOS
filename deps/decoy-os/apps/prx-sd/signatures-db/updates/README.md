# Signature Updates

This directory stores incremental update packages (delta patches).

## Format

Each update file is named `delta_{from}_{to}.bin` and contains:
- First 64 bytes: Ed25519 signature
- Remaining bytes: zstd-compressed `DeltaPatch` (bincode serialized)

## Usage

Updates are fetched automatically via `sd update` or manually placed here for offline use.
