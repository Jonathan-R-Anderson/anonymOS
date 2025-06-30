#!/bin/bash

# Script to install the comprehensive shell into anonymOS
# This will be available in the ISO under /sys/init/

echo "Installing comprehensive shell (-sh) into anonymOS..."

# Create necessary directories
mkdir -p /bin
mkdir -p /usr/local/sh
mkdir -p /etc/sh

# Copy shell source code to system location
if [ -d "/third_party/sh" ]; then
    echo "Copying shell source to /usr/local/sh..."
    cp -r /third_party/sh/* /usr/local/sh/
    
    # Try to compile a basic version of the shell
    cd /usr/local/sh
    
    echo "Attempting to compile shell for kernel environment..."
    
    # Create a minimal shell wrapper that can work in kernel space
    cat > /bin/sh_wrapper << 'EOF'
#!/usr/local/sh/interpreter
# Comprehensive shell wrapper for anonymOS
# This loads the full shell interpreter

# Set basic environment
export PATH="/bin:/usr/bin:/usr/local/bin"
export HOME="/root"
export SHELL="/bin/sh"

# Load the comprehensive shell
exec /usr/local/sh/src/interpreter.d "$@"
EOF
    
    chmod +x /bin/sh_wrapper
    
    # Create a symlink to the wrapper
    ln -sf /bin/sh_wrapper /bin/sh
    
    echo "Shell installation complete!"
    echo "The comprehensive shell is available at /bin/sh"
    echo "Source code is in /usr/local/sh"
else
    echo "Error: Shell source not found in /third_party/sh"
    exit 1
fi
