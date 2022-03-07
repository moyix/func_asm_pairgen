#!/usr/bin/env python
# Scan a directory tree and find any ELF files.

import os
import sys
from pathlib import Path

# Walk recursively through the directory tree, and find any ELF files.
def scan_dir(dir, cache_file=None):
    elf_files = []
    if cache_file and os.path.exists(cache_file):
        with open(cache_file, 'r') as f:
            for line in f:
                kind, path = line.split(None,1)
                kind = kind.strip()
                path = path.strip()
                elf_files.append((kind, path))
        return elf_files
    else:
        outf = open(cache_file, 'w')

    for root, dirs, files in os.walk(dir, followlinks=False):
        for fname in files:
            path = os.path.join(root, fname)
            if os.path.isfile(path) and not os.path.islink(path):
                try:
                    with open(path, 'rb') as f:
                        # Check if this is an ELF file, and print the type
                        # ET_NONE = 0, // No file type
                        # ET_REL = 1, // Relocatable file
                        # ET_EXEC = 2, // Executable file
                        # ET_DYN = 3, // Shared object file
                        # ET_CORE = 4, // Core file
                        if f.read(4) == b'\x7fELF':
                            f.seek(0x10, 0)
                            e_type = f.read(1)
                            if e_type == b'\x00':
                                kind = 'ET_NONE'
                            elif e_type == b'\x01':
                                kind = 'ET_REL'
                            elif e_type == b'\x02':
                                kind = 'ET_EXEC'
                            elif e_type == b'\x03':
                                kind = 'ET_DYN'
                            elif e_type == b'\x04':
                                kind = 'ET_CORE'
                            else:
                                kind = 'ET_UNKNOWN'
                            outf.write(f'{kind} {path}\n')
                            elf_files.append((kind, path))
                except:
                    pass
    outf.close()
    return elf_files
