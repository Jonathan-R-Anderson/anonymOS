# Build Script Consolidation

## Overview

All build scripts have been consolidated into a single unified `buildscript.sh` for easier maintenance and execution.

## Changes Made

### Integrated into `scripts/buildscript.sh`

1. **Font Library Building** (from `build_font_libs.sh`)
   - Builds FreeType and HarfBuzz as static libraries
   - Configures for freestanding kernel environment
   - Installs to sysroot
   - Location: Lines 221-318

2. **Kernel Linking** (updated)
   - Added `-lfreetype -lharfbuzz` to linker flags
   - Links font libraries into kernel
   - Location: Lines 464, 471

3. **Font Bundling** (new)
   - Copies SF Pro fonts to ISO
   - Destination: `/usr/share/fonts/` in ISO
   - Location: Lines 609-619

### Removed Scripts

The following standalone scripts have been removed as their functionality is now integrated:

- ✗ `scripts/build_font_libs.sh` - Integrated into main buildscript
- ✗ `scripts/build_openssl.sh` - Removed (unused)
- ✗ `scripts/build_x11_stack.sh` - Removed (unused)

## Build Process

The consolidated buildscript now follows this order:

1. **Config & Tool Checks**
2. **LLVM/Compiler-RT Builtins**
3. **POSIX Utilities**
4. **Desktop Stack Stubs**
5. **FreeType & HarfBuzz** ← NEW
6. **Kernel Compilation**
7. **Kernel Linking** (with font libs) ← UPDATED
8. **Shell (-sh)**
9. **ZSH & Oh-My-ZSH**
10. **GRUB & ISO Staging**
11. **Font Bundling** ← NEW
12. **Installation Assets**
13. **ISO Creation**

## Usage

### Single Command Build

```bash
./scripts/buildscript.sh
```

This now handles everything:
- ✅ Builds FreeType and HarfBuzz
- ✅ Links font libraries into kernel
- ✅ Bundles SF Pro fonts in ISO
- ✅ Creates bootable ISO

### Incremental Builds

The font library build is cached:
- FreeType: `build/font-libs/install/lib/libfreetype.a`
- HarfBuzz: `build/font-libs/install/lib/libharfbuzz.a`

If these files exist, they won't be rebuilt unless you delete them.

### Clean Build

```bash
rm -rf build/font-libs
./scripts/buildscript.sh
```

## Dependencies

The buildscript now requires:

### System Tools
- `cmake` - For FreeType build
- `meson` - For HarfBuzz build
- `ninja` - For Meson backend
- `clang` - C compiler
- `ldc2` - D compiler

### Install on Ubuntu/Debian
```bash
sudo apt-get install cmake meson ninja-build clang ldc
```

## Build Output

### Font Libraries
```
build/font-libs/
├── freetype-build/          # FreeType build directory
├── harfbuzz-build/          # HarfBuzz build directory
└── install/
    ├── lib/
    │   ├── libfreetype.a    # Static library
    │   └── libharfbuzz.a    # Static library
    └── include/
        ├── freetype2/       # FreeType headers
        └── harfbuzz/        # HarfBuzz headers
```

### Sysroot
```
$SYSROOT/usr/
├── lib/
│   ├── libfreetype.a        # Copied from build
│   └── libharfbuzz.a        # Copied from build
└── include/
    ├── freetype2/           # Copied from build
    └── harfbuzz/            # Copied from build
```

### ISO Contents
```
/usr/share/fonts/
├── SF-Pro.ttf               # San Francisco Pro Regular
└── SF-Pro-Italic.ttf        # San Francisco Pro Italic
```

## Troubleshooting

### Font Libraries Not Building

**Symptom:** Build skips font libraries
```
[!] FreeType or HarfBuzz source not found in 3rdparty/
[!] Skipping font library build (will use bitmap fonts only)
```

**Solution:** Clone FreeType and HarfBuzz
```bash
cd 3rdparty
git clone https://github.com/freetype/freetype.git
git clone https://github.com/harfbuzz/harfbuzz.git
```

### Fonts Not in ISO

**Symptom:** Fonts missing from ISO
```
[!] SF Pro fonts not found in 3rdparty/
```

**Solution:** Clone SF Pro fonts
```bash
cd 3rdparty
git clone https://github.com/sahibjotsaggu/San-Francisco-Pro-Fonts.git
```

### Linker Errors

**Symptom:** Undefined references to FreeType/HarfBuzz
```
undefined reference to `FT_Init_FreeType'
```

**Solution:** Ensure libraries are built and in sysroot
```bash
ls -la $SYSROOT/usr/lib/libfreetype.a
ls -la $SYSROOT/usr/lib/libharfbuzz.a
```

If missing, delete build cache and rebuild:
```bash
rm -rf build/font-libs
./scripts/buildscript.sh
```

## Benefits of Consolidation

✅ **Single Entry Point** - One script to build everything  
✅ **Correct Build Order** - Dependencies built in right sequence  
✅ **Easier Maintenance** - One file to update  
✅ **Better Caching** - Incremental builds work correctly  
✅ **Cleaner Repository** - Fewer scripts to manage  

## Migration Notes

If you had custom modifications to the old scripts:

### `build_font_libs.sh` → `buildscript.sh` lines 221-318
- Font library building section
- Same functionality, integrated

### `build_openssl.sh` → Removed
- OpenSSL not currently used
- Can be re-added if needed

### `build_x11_stack.sh` → Removed
- X11 not currently used
- Can be re-added if needed

## Next Steps

The buildscript is now ready for:

1. **Build Everything**
   ```bash
   ./scripts/buildscript.sh
   ```

2. **Test in QEMU**
   ```bash
   qemu-system-x86_64 -cdrom build/os.iso -m 512 -serial stdio
   ```

3. **Verify Fonts**
   - Check logs for `[✓] SF Pro fonts bundled`
   - Check logs for `[✓] Font libraries installed to sysroot`
   - Look for FreeType initialization messages at runtime
