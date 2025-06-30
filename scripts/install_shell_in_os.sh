#!/bin/bash

# Script to install and compile the comprehensive shell inside anonymOS
# This script will be available in the ISO at /sys/init/install_shell_in_os.sh

echo "Installing comprehensive shell (-sh) into anonymOS..."

# Create necessary directories
mkdir -p /bin
mkdir -p /usr/local/sh
mkdir -p /etc/sh
mkdir -p /tmp

# Check if shell source is available
if [ ! -d "/third_party/sh" ]; then
    echo "Error: Shell source not found at /third_party/sh"
    echo "The comprehensive shell source must be included in the ISO."
    exit 1
fi

# Check if DMD compiler is available
if [ ! -f "/bin/dmd" ]; then
    echo "Error: DMD compiler not found at /bin/dmd"
    echo "The D compiler must be included in the ISO."
    exit 1
fi

echo "Found shell source and DMD compiler."
echo "Setting up comprehensive shell compilation environment..."

# Copy shell source to a writable location
echo "Copying shell source to /usr/local/sh..."
cp -r /third_party/sh/* /usr/local/sh/

# Create compilation script
echo "Creating shell compilation script..."
cat > /tmp/compile_comprehensive_shell.sh << 'EOF'
#!/bin/sh
# Comprehensive shell compilation script for AnonymOS

echo "=== AnonymOS Comprehensive Shell Compiler ==="
echo "Compiling shell from /usr/local/sh/src..."

cd /usr/local/sh

# Try betterC compilation first (kernel-compatible)
echo "Attempting betterC compilation for kernel compatibility..."
if /bin/dmd -betterC -of=/bin/sh src/interpreter.d src/core/*.d src/commands/*.d; then
    echo "SUCCESS: Comprehensive shell compiled with betterC!"
    echo "Shell binary available at: /bin/sh"
    echo ""
    echo "The shell includes:"
    echo "  - 100+ built-in commands"
    echo "  - Job control and background processes"
    echo "  - Command history and aliases"
    echo "  - Interactive REPL"
    echo "  - Programming capabilities"
    echo ""
    echo "To launch the comprehensive shell, run: exec-sh"
    exit 0
fi

# Fallback to regular compilation
echo "BetterC compilation failed, trying regular compilation..."
if /bin/dmd -of=/bin/sh src/interpreter.d src/core/*.d src/commands/*.d; then
    echo "SUCCESS: Comprehensive shell compiled!"
    echo "Shell binary available at: /bin/sh"
    echo "To launch the comprehensive shell, run: exec-sh"
    exit 0
fi

echo "ERROR: Failed to compile comprehensive shell"
echo "Check that all source files are present and DMD is working correctly."
exit 1
EOF

chmod +x /tmp/compile_comprehensive_shell.sh

# Create a simple installer script
cat > /bin/install-sh << 'EOF'
#!/bin/sh
# Simple installer for the comprehensive shell
echo "Installing comprehensive shell..."
if [ -f "/tmp/compile_comprehensive_shell.sh" ]; then
    /tmp/compile_comprehensive_shell.sh
else
    echo "Error: Compilation script not found"
    echo "Run /sys/init/install_shell_in_os.sh first"
fi
EOF

chmod +x /bin/install-sh

echo "Comprehensive shell installation complete!"
echo ""
echo "To compile and install the shell:"
echo "  Method 1: Run 'install-sh' command"
echo "  Method 2: Run 'build-sh' from the built-in shell"
echo "  Method 3: Run /tmp/compile_comprehensive_shell.sh directly"
echo ""
echo "After compilation, use 'exec-sh' to launch the comprehensive shell."
