#!/usr/bin/env python3

from bisect import bisect_right

import humanize
from clang.cindex import Config
from source_extractor import get_source_bodies
from collections import defaultdict
from dwarfdump_parse import get_dwarf_info
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import NoteSection
from elftools.common.exceptions import ELFError
import multiprocessing as mp
import subprocess
import time
from operator import itemgetter
from pathlib import Path
import scan_elf
import argparse
import clang.cindex
import gas_parser
import json
import shutil
import os
import sys
import tempfile
from hashlib import sha1
from tabulate import tabulate
# IPython debugging
import IPython

# Don't proceed if we have less than 16GB of RAM.
MEM_CEILING = 16*1024*1024*1024

# Check if we have enough RAM and CPU, and if not, wait a bit
def wait_for_resources():
    # Get free memory
    def get_free_mem():
        # Get MemTotal, MemFree, Buffers, and Cached
        MemTotal = 0
        MemFree = 0
        Buffers = 0
        Cached = 0
        with open('/proc/meminfo') as f:
            for line in f:
                if line.startswith('MemFree'):
                    MemFree = int(line.split()[1])
                elif line.startswith('MemTotal'):
                    MemTotal = int(line.split()[1])
                elif line.startswith('Buffers'):
                    Buffers = int(line.split()[1])
                elif line.startswith('Cached'):
                    Cached = int(line.split()[1])
        MemUsed = MemTotal - (MemFree + Buffers + Cached)
        FreeKB = MemTotal - MemUsed
        return FreeKB * 1024
    # Get load avg
    def get_load_avg():
        with open('/proc/loadavg') as f:
            return float(f.read().split()[0])
    while True:
        mem = get_free_mem()
        load = get_load_avg()
        if mem < MEM_CEILING:
            memstr = humanize.naturalsize(mem, binary=True)
            print(f"System overloaded (free mem = {memstr}), waiting for resources...")
            time.sleep(5)
        elif load > 100:
            print(f"System overloaded (load avg = {load}), waiting for resources...")
            time.sleep(5)
        else:
            break

# Infinitely expanding defaultdict
expanding_dict = lambda: defaultdict(expanding_dict)

class MiniTimer:
    def __init__(self):
        self.tracked = {}
        self.totals = defaultdict(int) 
    def start(self, name):
        self.tracked[name] = time.time()
    def end(self, name):
        self.tracked[name] = time.time() - self.tracked[name]
        print(f"{name} took {self.tracked[name]} seconds")
        self.totals[name] += self.tracked[name]
        del self.tracked[name]
    def print_totals(self):
        all_times = [(v,k) for k,v in self.totals.items()]
        all_times = sorted(all_times, key=itemgetter(0), reverse=True)
        print(tabulate(all_times, headers=["Time", "Name"]))

CACHE_DWARF = True

def make_relative(path, root):
    try:
        return str(Path(path).relative_to(root))
    except ValueError:
        return path

# Pain points right now:
# - We don't have a good way to go from a DWARF CU to a specific command in the
#   compilation database. Right now we just pick the first one that works, but
#   can we do better by matching the CU to the command somehow?

# Manual path to the libclang.so.
LIBCLANG_PATH= '/usr/lib/llvm-14/lib/libclang-14.so.1'
Config.set_library_file(LIBCLANG_PATH)

ARCHIVE_PATH = Path("/data/research/debbuild_artifacts/")
ELF_MAP = Path('/fastdata2/exe_maps')
LOG_DIR = Path('/fastdata2/rebuild_logs')
OLD_ROOT = Path("/fastdata/debian_allsrc/build")
NEW_ROOT = Path("/build")

PKG_VERSION_MAP = '/fastdata2/pkg_version_map.txt'
BUILD_DEP_ROOT = '/fastdata2/builddep_debs'
BUILD_DEP_MAP = BUILD_DEP_ROOT + '/.meta/all_builddep_pkgvers.txt'
def find_build_deps(pkg):
    for line in open(PKG_VERSION_MAP):
        parts = line.strip().split()
        if parts[0] == pkg:
            name = parts[1]
            ver= parts[3]
            fullver = parts[4]
            break
    else:
        print(f"No build deps found for {pkg}")
        return []
    deps = []
    for line in open(BUILD_DEP_MAP):
        parts = line.strip().split()
        if parts[0] == name:
            deps.append(parts[1])
    debs = []
    for d in deps:
        depname, depver, deparch = d.split('_')
        if ':' in depver: depver = depver.split(':')[1]
        debfile = os.path.join(BUILD_DEP_ROOT, f'{depname}_{depver}_{deparch}.deb')
        udebfile = os.path.join(BUILD_DEP_ROOT, f'{depname}_{depver}_{deparch}.udeb')
        if os.path.exists(debfile):
            debs.append(debfile)
        elif os.path.exists(udebfile):
            debs.append(udebfile)
        else:
            print(f"No deb found for {d}")
    return debs

def load_elf_map(root, pkg):
    elf_files = scan_elf.scan_dir(root, ELF_MAP/f"{pkg}.txt")
    elf_map = []
    for kind, path in elf_files:
        if kind == 'ET_DYN' or kind == 'ET_EXEC':
            elf_map.append(path)
    return elf_map

def get_build_id(elf):
    for sect in elf.iter_sections():
        if not isinstance(sect, NoteSection):
            continue
        for note in sect.iter_notes():
            desc = note['n_desc']
            if note['n_type'] == 'NT_GNU_BUILD_ID':
                return desc
    return ''

# Get bytes from an ELF file using pyelftools.
_elf_seg_cache = {}
def load_bytes_from_elf(b, elf, vaddr, size):
    if _elf_seg_cache.get(b) is None:
        _elf_seg_cache[b] = []
        for segment in elf.iter_segments():
             _elf_seg_cache[b].append( (segment.header.p_vaddr, segment.header.p_memsz, segment) )
        _elf_seg_cache[b].sort(key=itemgetter(0))
        addrs = [x[0] for x in _elf_seg_cache[b]]
        segs = [x[2] for x in _elf_seg_cache[b]]
        _elf_seg_cache[b] = (addrs, segs)
    # Binary search for the segment containing the offset.
    addrs, segs = _elf_seg_cache[b]
    i = bisect_right(addrs, vaddr)
    if i == 0:
        return None
    seg = segs[i-1]
    if seg.header.p_vaddr <= vaddr < seg.header.p_vaddr+seg.header.p_memsz:
        # Read the bytes from the segment.
        off = vaddr - seg.header.p_vaddr
        return seg.data()[off:off+size]
    else:
        return None

parser = argparse.ArgumentParser()
parser.add_argument('mode', choices=['binary_comments', 'asm_source'], help='Which mode to run in.')
parser.add_argument('compile_commands', default='compile_commands.json',
    type=str, help='compile_commands.json file')
parser.add_argument('-o', '--output', default='output.json')
parser.add_argument('-b', '--binary', required=False, help='Only work on this binary')
args = parser.parse_args()

if not os.path.exists(args.compile_commands):
    parser.error('No compile_commands.json found -- maybe you need to build the project with bear?')

# Keep track of times taken
tm = MiniTimer()

# We want to do two related things here:
# 1. For each binary that was produced, pull out the bytes of each function,
#    find the matching source file, and save the function bytes, source, and
#    comments. (This is what Kazi needs for his NN ASM -> Comment model.)
# 2. For each compilation command, find the source and the asm file, and
#    then write out pairs of (source, asm) for each function in the file. This
#    is what BDG needs for training his ASM -> Source model (decompilation).

# Let's find the package name
database = json.load(open(args.compile_commands))
for command in database:
    dir = Path(command['directory'])
    if str(dir).startswith(str(OLD_ROOT)):
        ROOT = OLD_ROOT
        # Get the package name from the directory
        break
    elif str(dir).startswith(str(NEW_ROOT)):
        ROOT = NEW_ROOT
        break
else:
    print(f"No root found in {database}", file=sys.stderr)
    sys.exit(1)
pkg_name = dir.relative_to(ROOT).parts[0]

# Install build dependencies so that hopefully the environment
# is very similar to the one used to compile the source files.
tm.start('install_build_deps')
if not os.path.exists('/tmp/builddeps_installed.stamp'):
    debs = find_build_deps(pkg_name)
    subprocess.run(['sudo', '-E', 'dpkg', '-i', '--force-all'] + debs)
    subprocess.run(['sudo', '-E', 'apt-get', '-y', '-f', 'install'])
    # Mark that we've done this so that we don't do it again.
    open('/tmp/builddeps_installed.stamp', 'w').close()
tm.end('install_build_deps')

# Both modes need the compile db
# libclang wants it to be in a directory, so make one and symlink
td = tempfile.mkdtemp()
cc_path = os.path.abspath(args.compile_commands)
# Add parse-all-comments to the command line for each arg
# so that we get all the comments in the file.
cc = json.load(open(cc_path))
# for cmd in cc: cmd['arguments'].append('-fparse-all-comments')
json.dump(cc, open(os.path.join(td, 'compile_commands.json'), 'w'))
compdb = clang.cindex.CompilationDatabase.fromDirectory(td)

# Copy the source files back to where they were at compile time
tm.start('copy_source')
src = ARCHIVE_PATH / pkg_name
dest = ROOT / pkg_name
if not dest.exists():
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"Copying over source files from {src} to {dest}")
    subprocess.check_call(['cp', '-a', str(src), str(dest)])
SOURCE_PATH = ROOT / pkg_name
tm.end('copy_source')

if args.mode == 'binary_comments':
    if args.binary is None:
        # Load the ELF map
        tm.start('load_elf_map')
        binaries = load_elf_map(SOURCE_PATH, pkg_name)
        tm.end('load_elf_map')
    else:
        binaries = [args.binary]
    

    seen_buildids = set()
    # Get a list of functions and source files from the binary. Uses DWARF info.
    bin_functions = defaultdict(list)
    bin_cus = defaultdict(list)
    binary_worklist = []
    for b in binaries:
        # Skip debug-only binaries and symlinks
        if '.build-id' in b or b.endswith('.debug') or os.path.islink(b):
            continue
        print(f"Getting DWARF info for {b}...", end='')
        try:
            elf = ELFFile(open(b, 'rb'))
        except ELFError:
            continue
        # Skip binaries that don't have DWARF info
        if not elf.has_dwarf_info():
            print("no DWARF info")
            continue
        # Skip binaries that aren't x86-64
        if elf.get_machine_arch() != 'x64':
            print("Not x86-64")
            continue
        build_id = get_build_id(elf)
        if build_id in seen_buildids:
            print(f"Already seen, skipping.")
            continue
        else:
            print()
        tm.start('get_dwarf_info')
        h = sha1(b.encode()).hexdigest()
        if not os.path.exists(f'{h}.json'):
            dwarf = get_dwarf_info(b, SOURCE_PATH)
            if CACHE_DWARF: json.dump(dwarf, open(f'{h}.json', 'w'))
        else:
            print(f"Loading cached DWARF info for {b} from {h}.json", file=sys.stderr)
            dwarf = json.load(open(f'{h}.json'))
        tm.end('get_dwarf_info')
        cus = dwarf
        if not cus: continue
        tm.start('get_function_bytes')
        print(f"Getting function bytes for {b}...")
        for cu in cus:
            # Skip CUs that aren't C/C++
            if not cu['language'].startswith('DW_LANG_C'): continue
            bin_cus[b].append(cu)
            for func in cu['functions']:
                func_bytes = load_bytes_from_elf(b, elf, func['low_pc'], func['high_pc'] - func['low_pc'])
                if func_bytes is None: continue
                func['bytes'] = func_bytes.hex()
                bin_functions[b].append(func)
        tm.end('get_function_bytes')
        if len(bin_functions[b]) > 0:
            seen_buildids.add(build_id)
        print(f"Found {len(bin_functions[b])} functions in {b}")
    # Clear this now
    _elf_seg_cache = {}

    # Each CU can have many functions, and each function could come from some
    # other file than the current CU. So our map looks like:
    # binary:            // The binary we're working on
    #   cu:              // The CU in the binary
    #     decl_file:     // The file that the declaration came from
    #       func_name:   // The name of the function
    #         func       // The function object
    bin_functions_by_file = expanding_dict()
    for b in bin_functions:
        for func in bin_functions[b]:
            cu = func['cu_file']
            decl_file = func['decl_file']
            name = func['name']
            bin_functions_by_file[b][cu][decl_file][name] = func

    # We only care about binaries that have functions/CUs
    nbins_before = len(binaries)
    binaries = bin_functions.keys()
    nbins_after = len(binaries)
    print(f"Threw away {nbins_before - nbins_after} binaries with no functions/CUs")

    # Parse the source for each CU
    bin_src = {}
    for b in bin_cus:
        bin_src[b] = {}
        tm.start('get_source_bodies')
        print(f"Parsing source files for {b}...")
        wait_for_resources()
        def src_body_helper(src):
            src_bodies = get_source_bodies(src,td)
            return src, src_bodies
        sources_set = set([cu['source'] for cu in bin_cus[b]])
        sources = [cu['source'] for cu in bin_cus[b] if os.path.exists(cu['source'])]
        with mp.Pool(mp.cpu_count()) as pool:
            results = pool.map(src_body_helper, sources)
        for src, bodies in results:
            bin_src[b][src] = bodies
            sources_set.remove(src)
        for src in sources_set:
            print(f"SrcParse {src} NOT FOUND")
        tm.end('get_source_bodies')

    # Debug: print out everything
    # for b in binaries:
    #     print("="*20 + f" {b} " + "="*20)
    #     for func in bin_functions[b]:
    #         print(f"BIN {func['decl_file']} {func['name']} {func['low_pc']:#x}-{func['high_pc']:#x}")
    #     for src in bin_src[b]:
    #         for func in bin_src[b][src]:
    #             print(f"SRC {src} {func}")

    # This has the same structure as bin_functions_by_file, but comes from parsing
    # the source files.
    src_functions_by_file = expanding_dict()
    for b in bin_src:
        for cu_src in bin_src[b]:
            for func_name in bin_src[b][cu_src]:
                func = bin_src[b][cu_src][func_name]
                decl_file = func['file']
                src_functions_by_file[b][cu_src][decl_file][func_name] = func

    bincu_stats = expanding_dict()
    tm.start('bin_src matching')
    outfile = open(args.output, 'w')
    # Write out the JSON
    for b in binaries:
        print(f"Writing JSON for {b}...")
        for cu in bin_functions_by_file[b]:
            bincu_stats[b][cu]['total'] = 0
            bincu_stats[b][cu]['found'] = 0
            for decl_file in bin_functions_by_file[b][cu]:
                for func_name in bin_functions_by_file[b][cu][decl_file]:
                    bincu_stats[b][cu]['total'] += 1
                    bin_func = bin_functions_by_file[b][cu][decl_file][func_name]
                    # print(f"Looking for {func_name} from {cu} declared in {decl_file}: ", end='')
                    src_func = src_functions_by_file[b][cu][decl_file][func_name]
                    if not src_func:
                        # print("MISSED")
                        continue
                    else:
                        # print("FOUND")
                        bincu_stats[b][cu]['found'] += 1
                    bin_func['src_body'] = src_func['body']
                    comments = []
                    for fname, line, comment in src_func['comments']:
                        fname = make_relative(fname, SOURCE_PATH)
                        comments.append( (fname, line, comment) )
                    bin_func['src_comments'] = comments
                    bin_func['src_lines'] = [src_func['start'], src_func['end']]
                    bin_func['package'] = pkg_name
                    bin_func['decl_file'] = make_relative(decl_file, SOURCE_PATH)
                    bin_func['binary'] = make_relative(b, SOURCE_PATH)
                    print(json.dumps(bin_func), file=outfile)
    outfile.close()
    tm.end('bin_src matching')

    # Print out stats about the binary/CU function matching
    print(f"Bin/CU stats:")
    grand_total = 0
    grand_found = 0
    headers = ['Binary', 'Compilation Unit', 'Found', 'Total']
    rows = []
    for b in bincu_stats:
        brel = make_relative(b, SOURCE_PATH)
        for cu in bincu_stats[b]:
            curel = make_relative(cu, SOURCE_PATH)
            found = bincu_stats[b][cu]['found']
            total = bincu_stats[b][cu]['total'] 
            grand_found += found
            grand_total += total
            rows.append( [brel, curel, found, total] )
    print(tabulate(rows, headers))
    print(f"Grand Total: {grand_found:5} / {grand_total:5}")

    tm.print_totals()

# Cleanup
# Remove compile_commands.json
os.unlink(os.path.join(td, 'compile_commands.json'))
os.rmdir(td)

sys.exit(0)

# # Last piece: Parse the asm file for each source file
# asm = gas_parser.parse_asm(open(args.asm))

# asm_function_names = set(asm['functions'].keys())
# source_function_names = set(source_bodies.keys())
# with open(args.output, 'w') as f:
#     for fun in asm_function_names & source_function_names:
#         paired = {}
#         paired['asm'] = '\n'.join(asm['functions'][fun]['body'])
#         paired['source'] = source_bodies[fun]
#         paired['name'] = fun
#         paired['source_path'] = args.src
#         print(json.dumps(paired), file=f)
#         src_lines = len(paired['source'].split('\n'))
#         asm_lines = len(paired['asm'].split('\n'))
#         print(f'{fun:<40} {asm_lines:4} aLoC {src_lines:4} sLoC {asm_lines/src_lines:.2f}')
