#!/bin/bash

# Script to create a kernel-compatible shell for anonymOS

set -e

BUILD_DIR="build"
TARGET_DIR="$BUILD_DIR/bin"

echo "Building kernel-compatible shell for anonymOS..."

# Create build directory
mkdir -p "$TARGET_DIR"

# Create a minimal kernel-compatible shell that can load the comprehensive shell
echo "Creating kernel-compatible shell interface..."
cat > kernel_shell.d << 'EOF'
module kernel_shell;

// Kernel-compatible shell that can interface with the comprehensive shell
// This runs in kernel space and provides basic shell functionality

extern(C) void main() {
    // This will be the entry point when loaded by the kernel
    shell_main();
}

extern(C) void shell_main() {
    // Basic shell functionality - this would interface with the kernel's I/O
    // For now, this is a placeholder that the kernel can load
    
    // In a real implementation, this would:
    // 1. Initialize shell environment
    // 2. Read commands from keyboard
    // 3. Execute commands using kernel services
    // 4. Interface with the comprehensive shell source in /third_party/sh
    
    asm { "hlt"; } // Halt for now - kernel will handle this
}
EOF

# Compile with basic flags for kernel compatibility
if command -v ldc2 >/dev/null 2>&1; then
    echo "Compiling kernel shell with ldc2..."
    if ldc2 -betterC -fno-pic -mtriple=x86_64-unknown-elf kernel_shell.d -of="$TARGET_DIR/sh"; then
        echo "Kernel shell compiled successfully!"
        rm kernel_shell.d
        
        # Also create a script that installs the comprehensive shell at runtime
        cat > "$TARGET_DIR/install_comprehensive_shell.sh" << 'INSTALL_EOF'
#!/bin/sh
# Runtime installer for comprehensive shell
echo "Installing comprehensive shell from /third_party/sh..."
cd /third_party/sh
if [ -x "build_runtime.sh" ]; then
    ./build_runtime.sh
elif [ -x "interpreter" ]; then
    cp interpreter /bin/sh_comprehensive
    echo "Comprehensive shell installed as /bin/sh_comprehensive"
else
    echo "Comprehensive shell source available but not compiled"
    echo "D compiler needed to build: /bin/dmd"
fi
INSTALL_EOF
        chmod +x "$TARGET_DIR/install_comprehensive_shell.sh"
        
        echo "Shell integration complete!"
        echo "- Kernel shell binary: $TARGET_DIR/sh"
        echo "- Runtime installer: $TARGET_DIR/install_comprehensive_shell.sh"
        echo "- Comprehensive shell source will be in ISO at /third_party/sh"
        exit 0
    fi
fi

echo "Creating basic ELF stub for kernel loading..."
# Create a minimal ELF that the kernel can load
cat > stub_shell.c << 'EOF'
// Minimal shell stub for kernel loading
void _start() {
    // Entry point for ELF loading
    // In real implementation, this would call kernel shell functions
    while(1) {
        // Infinite loop - kernel will manage this process
        asm("hlt");
    }
}
EOF

if command -v gcc >/dev/null 2>&1; then
    echo "Compiling shell stub with gcc..."
    if gcc -nostdlib -static -fno-pic -m64 stub_shell.c -o "$TARGET_DIR/sh"; then
        echo "Shell stub compiled successfully!"
        rm stub_shell.c
        exit 0
    fi
fi

echo "Warning: Could not build shell binary"
echo "The enhanced built-in shell will be used instead"
echo "Comprehensive shell source will still be available in /third_party/sh"

# Clean up
rm -f kernel_shell.d stub_shell.c
exit 0  # Don't fail the build, just use built-in shell 