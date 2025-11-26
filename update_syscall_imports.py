#!/usr/bin/env python3
"""
Update import statements to reflect new syscalls module structure.
"""
import os
import re
from pathlib import Path

def update_syscall_imports(filepath):
    """Update syscall-related imports in a file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        
        # Update specific module imports
        replacements = [
            (r'\bimport anonymos\.kernel\.syscalls\b', 'import anonymos.syscalls.syscalls'),
            (r'\bimport anonymos\.kernel\.linux_syscalls\b', 'import anonymos.syscalls.linux'),
            (r'\bimport anonymos\.kernel\.cap_syscalls\b', 'import anonymos.syscalls.capabilities'),
            (r'\bimport anonymos\.posix\b', 'import anonymos.syscalls.posix'),
            (r'\bimport anonymos\.posix_compat\b', 'import anonymos.syscalls.posix_compat'),
            (r'\bfrom anonymos\.kernel\.syscalls\b', 'from anonymos.syscalls.syscalls'),
            (r'\bfrom anonymos\.kernel\.linux_syscalls\b', 'from anonymos.syscalls.linux'),
            (r'\bfrom anonymos\.kernel\.cap_syscalls\b', 'from anonymos.syscalls.capabilities'),
            (r'\bfrom anonymos\.posix\b', 'from anonymos.syscalls.posix'),
            (r'\bfrom anonymos\.posix_compat\b', 'from anonymos.syscalls.posix_compat'),
        ]
        
        for pattern, replacement in replacements:
            content = re.sub(pattern, replacement, content)
        
        if content != original_content:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        return False
    except Exception as e:
        print(f"Error processing {filepath}: {e}")
        return False

def main():
    root_dir = Path('/home/jonny/Documents/internetcomputer')
    
    # Process all D source files
    d_files = list(root_dir.glob('src/**/*.d'))
    
    modified_count = 0
    for filepath in d_files:
        if update_syscall_imports(filepath):
            modified_count += 1
            print(f"Modified: {filepath}")
    
    print(f"\nTotal files modified: {modified_count}")

if __name__ == '__main__':
    main()
