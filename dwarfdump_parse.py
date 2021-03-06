#!/usr/bin/env python
# Invoke llvm-dwarfdump-14 and parse the output.

import os
from pathlib import Path
import subprocess
import json
import sys

def n(path):
    return os.path.normpath(path)

def ex(path):
    return os.path.exists(path)

def get_dwarf_info(exe, srcdir):
    srcdir = str(srcdir)
    src = Path(srcdir)
    try:
        output = subprocess.check_output(['llvm-dwarfdump-14', exe]).decode('utf-8')
    except subprocess.CalledProcessError as e:
        print('llvm-dwarfdump-14 failed:', e, file=sys.stderr)
        return []
    lines = output.splitlines()
    compile_units = []
    rename_cache = {}
    current_cu = None
    incomplete_functions = {}
    i = 0
    MAX_LINES = len(lines)
    while i < MAX_LINES:
        line = lines[i].strip()
        if line.endswith('DW_TAG_compile_unit'):
            cu = {}
            incomplete_functions = {}
            while line:
                i += 1
                if i >= MAX_LINES:
                    break
                line = lines[i].strip()
                if line.startswith('DW_AT_name'):
                    cu['name'] = line.split('"')[1].strip()
                elif line.startswith('DW_AT_comp_dir'):
                    cu['comp_dir'] = line.split('"')[1].strip()
                elif line.startswith('DW_AT_language'):
                    cu['language'] = line.split('(')[1][:-1].strip()

            if 'comp_dir' not in cu:
                cu['comp_dir'] = srcdir

            if 'name' not in cu:
                current_cu = None
                continue

            # Try to resolve the source file name
            fname = Path(cu['name'])
            compdir = Path(cu['comp_dir'])
            if ex(src/compdir/fname):
                cu['source'] = str(n(src/compdir/fname))
            elif ex(src/fname):
                cu['source'] = str(n(src/fname))
            else:
                cu['source'] = str(n(cu['name']))
            cu['functions'] = []
            if 'language' not in cu:
                cu['language'] = 'DW_LANG_C' # Bad assumption?
            compile_units.append(cu)
            current_cu = compile_units[-1]
        elif line.endswith('DW_TAG_subprogram'):
            func = {}
            while line:
                i += 1
                if i >= MAX_LINES:
                    break
                # Skip parsing if we're outside a CU (or if the CU was invalid)
                if not current_cu:
                    break
                line = lines[i].strip()
                try:
                    if line.startswith('DW_AT_name'):
                        func['friendly_name'] = line.split('"')[1].strip()
                    elif line.startswith('DW_AT_specification'):
                        func['linkage_name'] = line.split('"')[1].strip()
                    elif line.startswith('DW_AT_low_pc'):
                        func['low_pc'] = int(line.split('(')[1][:-1], 0)
                    elif line.startswith('DW_AT_high_pc'):
                        func['high_pc'] = int(line.split('(')[1][:-1], 0)
                    elif line.startswith('DW_AT_decl_file'):
                        func['decl_file'] = line.split('"')[1].strip()
                    elif line.startswith('DW_AT_linkage_name'):
                        func['linkage_name'] = line.split('"')[1].strip()
                except IndexError:
                    continue
            if 'linkage_name' in func:
                func['name'] = func['linkage_name']
            elif 'friendly_name' in func:
                func['name'] = func['friendly_name']
            else:
                continue

            # Some functions' information is split across multiple entries
            if func['name'] in incomplete_functions:
                func.update(incomplete_functions[func['name']])

            # Fix the decl_file
            if 'decl_file' not in func:
                if func['name'] in incomplete_functions:
                    incomplete_functions[func['name']].update(func)
                else:
                    incomplete_functions[func['name']] = func
                continue
            if func['decl_file'] in rename_cache:
                func['decl_file'] = rename_cache[func['decl_file']]
            else:
                old_fname = func['decl_file']
                fname = Path(func['decl_file'])
                if fname.is_absolute(): # Leave absolute paths alone but normalize them
                    func['decl_file'] = str(n(fname))
                else:
                    # Might be relative to the current CU, but broken
                    current_cu = compile_units[-1]
                    try:
                        fname_relative = fname.relative_to(current_cu['comp_dir'])
                        if ex(src/fname_relative):
                            func['decl_file'] = str(n(src/fname_relative))
                        elif ex(src/fname): # Simple relative path
                            func['decl_file'] = str(n(src/fname))
                    except ValueError:
                        # Give up
                        pass
                rename_cache[old_fname] = func['decl_file']

            current_cu = compile_units[-1]
            func['cu_file'] = current_cu['source']

            if ('name' in func and 
                'low_pc' in func and 
                'high_pc' in func and 
                func['low_pc'] and func['high_pc'] and
                'decl_file' in func):
                current_cu['functions'].append(func)
                if func['name'] in incomplete_functions:
                    del incomplete_functions[func['name']]
            else:
                if func['name'] not in incomplete_functions:
                    incomplete_functions[func['name']] = func
                else:
                    incomplete_functions[func['name']].update(func)
        i += 1
    return compile_units

if __name__  == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Parse DWARF info from an executable')
    parser.add_argument('exe', help='Executable to parse')
    parser.add_argument('srcdir', help='Source directory')
    args = parser.parse_args()
    print(json.dumps(get_dwarf_info(args.exe, args.srcdir)))
