#!/usr/bin/env python3
"""
Refactor script to rename minimal_os to anonymos throughout the codebase.
"""
import os
import re
from pathlib import Path

def refactor_file(filepath):
    """Refactor a single file to replace minimal_os with anonymos."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        
        # Replace module declarations
        content = re.sub(r'\bmodule minimal_os\.', 'module anonymos.', content)
        
        # Replace import statements
        content = re.sub(r'\bimport minimal_os\.', 'import anonymos.', content)
        content = re.sub(r'\bfrom minimal_os\.', 'from anonymos.', content)
        
        # Replace public imports
        content = re.sub(r'\bpublic import minimal_os\.', 'public import anonymos.', content)
        
        # Replace package references
        content = re.sub(r'\bpackage\(minimal_os\)', 'package(anonymos)', content)
        
        # Replace string literals and comments that reference the module path
        content = re.sub(r'"minimal_os\.', '"anonymos.', content)
        content = re.sub(r'minimal_os\.', 'anonymos.', content)
        
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
    
    # Process D source files
    d_files = list(root_dir.glob('src/**/*.d'))
    
    # Process assembly files
    asm_files = list(root_dir.glob('src/**/*.s'))
    
    # Process build script
    build_scripts = [root_dir / 'buildscript.sh']
    
    all_files = d_files + asm_files + build_scripts
    
    modified_count = 0
    for filepath in all_files:
        if refactor_file(filepath):
            modified_count += 1
            print(f"Modified: {filepath}")
    
    print(f"\nTotal files modified: {modified_count}")

if __name__ == '__main__':
    main()
