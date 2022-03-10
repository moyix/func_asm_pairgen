#!/usr/bin/env python3

from bisect import bisect_right
import humanize
from clang.cindex import Config
from collections import defaultdict
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import NoteSection
from elftools.common.exceptions import ELFError
import subprocess
import time
from operator import itemgetter
from pathlib import Path
import scan_elf
import argparse
import clang.cindex
import json
import os
import sys
import tempfile
from hashlib import sha1
from tabulate import tabulate
# IPython debugging
import IPython

# Don't proceed if we have less than 64GB of RAM.
MEM_CEILING = 64*1024*1024*1024

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

# Check if we have enough RAM and CPU, and if not, wait a bit
def wait_for_resources():
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
        all_times.append((sum(v for v,_ in all_times), "Total"))
        print(tabulate(all_times, headers=["Time", "Name"]))

CACHE_DWARF = True
CACHE_SOURCE = True

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
        for segment in elf.iter_segments(type='PT_LOAD'):
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

# Helper to launch dwarfdump_parse.py on an array of binaries
# and collect the outputs.
def get_dwarf_helper(batch):
    BASEDIR = os.path.dirname(os.path.realpath(__file__))
    DWARFDUMP = os.path.join(BASEDIR, 'dwarfdump_parse.py')
    hashfiles = len(batch)*[None]
    results = len(batch)*[None]
    procs = len(batch)*[None]
    for i, (b, source_path) in enumerate(batch):
        print(f"Getting DWARF info for {b}...")
        h = sha1(b.encode()).hexdigest()
        hashfiles[i] = f'{h}.json'
        if not os.path.exists(f'{h}.json'):
            print(f"Caching DWARF info for {b} to {h}.json...")
            p = subprocess.Popen(['python3', DWARFDUMP, b, source_path], stdout=open(f'{h}.json', 'w'))
            procs[i] = p
        else:
            print(f"Loading cached DWARF info for {b} from {h}.json...")
    for i, p in enumerate(procs):
        if p: p.wait()
        results[i] = json.load(open(hashfiles[i]))
        print(f"Found {len(results[i])} CUs for {batch[i][0]}")
    return results

def get_src_bodies_helper(batch):
    BASEDIR = os.path.dirname(os.path.realpath(__file__))
    SRCBODIES = os.path.join(BASEDIR, 'source_extractor.py')
    hashfiles = len(batch)*[None]
    results = len(batch)*[None]
    procs = len(batch)*[None]
    for i, (src_cu, temp_dir) in enumerate(batch):
        cu_src = src_cu['source']
        print(f"Getting source bodies for {cu_src}...")
        h = sha1(cu_src.encode()).hexdigest()
        hashfiles[i] = f'{h}.json'
        if not os.path.exists(f'{h}.json'):
            print(f"Caching src bodies for {cu_src} to {h}.json...")
            p = subprocess.Popen(['python3', SRCBODIES, temp_dir, cu_src], stdout=open(f'{h}.json', 'w'))
            procs[i] = p
        else:
            print(f"Loading cached src bodies for {cu_src} from {h}.json...")
    for i, p in enumerate(procs):
        if p: p.wait()
        results[i] = json.load(open(hashfiles[i]))
        print(f"Found {len(results[i])} source bodies for {batch[i][0]['source']}")
    return results

def binary_comments(args):
    tm = args.tm
    if not args.binary:
        # Load the ELF map
        tm.start('load_elf_map')
        binaries = load_elf_map(args.SOURCE_PATH, args.pkg_name)
        tm.end('load_elf_map')
    else:
        binaries = args.binary
    
    # Get a list of functions and source files from the binary. Uses DWARF info.
    binary_worklist = []
    for b in binaries:
        # Skip debug-only binaries and symlinks
        if '.build-id' in b or b.endswith('.debug') or os.path.islink(b):
            continue
        try:
            elf = ELFFile(open(b, 'rb'))
            # Skip binaries that don't have DWARF info
            if not elf.has_dwarf_info():
                continue
            # Skip binaries that aren't x86-64
            if elf.get_machine_arch() != 'x64':
                continue
            build_id = get_build_id(elf)
            binary_worklist.append((b, elf, build_id))
        except ELFError:
            continue

    BATCH_SIZE = 32

    bincu_stats = expanding_dict()
    outfile = open(args.output, 'w')

    seen_buildids = set()
    for i in range(0, len(binary_worklist), BATCH_SIZE):
        bin_functions = defaultdict(list)
        bin_cus = defaultdict(list)
        dwarfbatch = binary_worklist[i:i+BATCH_SIZE]
        dwarfmpbatch = [(b[0],args.SOURCE_PATH) for b in dwarfbatch]
        print(f"Processing {len(dwarfbatch)} binaries")
        tm.start('get_dwarf_info')
        results = get_dwarf_helper(dwarfmpbatch)
        tm.end('get_dwarf_info')
        for dwarf, (b, elf, build_id) in zip(results, dwarfbatch):
            cus = dwarf
            if not cus: continue
            if build_id in seen_buildids: continue
            tm.start('get_function_bytes')
            print(f"Getting function bytes for {b}...")
            for cu in cus:
                # Skip CUs that aren't C/C++
                if not cu['language'].startswith('DW_LANG_C'): continue
                bin_cus[b].append(cu)
                for func in cu['functions']:
                    # print("Getting function bytes for", func['name'], "...", file=sys.stderr, end='', flush=True)
                    func_bytes = load_bytes_from_elf(b, elf, func['low_pc'], func['high_pc'] - func['low_pc'])
                    if func_bytes is None:
                        # print("failed.", file=sys.stderr)
                        continue
                    else:
                        # print("success.", file=sys.stderr)
                        pass
                    func['bytes'] = func_bytes.hex()
                    bin_functions[b].append(func)
            tm.end('get_function_bytes')
            print(f"Found {len(bin_functions[b])} functions in {b}")
            if len(bin_functions[b]) > 0:
                seen_buildids.add(build_id)
        
        # Clear this cache now
        global _elf_seg_cache
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

        # Parse the source for each CU
        for b in bin_cus:
            tm.start('get_source_bodies')
            print(f"Parsing source files for {b}...")
            # Work in batches of BATCH_SIZE in parallel
            for j in range(0, len(bin_cus[b]), BATCH_SIZE):
                srcbatch = bin_cus[b][j:j+BATCH_SIZE]
                srcmpbatch = [ (cu, args.td) for cu in srcbatch ]
                srcbatch_results = get_src_bodies_helper(srcmpbatch)

                for cu, src_bodies in zip(srcbatch, srcbatch_results):
                    cu_src = cu['source']
                    print(f"Attempting matching for {cu_src}...")
                    if cu_src.endswith('transition_affine.c'): IPython.embed(colors='Linux')
                    print("Will look in:", list(bin_functions_by_file[b][cu_src]))
                    bincu_stats[b][cu_src]['total'] = 0
                    bincu_stats[b][cu_src]['found'] = 0
                    # Do all the matching and write out to the JSON file
                    for decl_file in bin_functions_by_file[b][cu_src]:
                        for func_name in bin_functions_by_file[b][cu_src][decl_file]:
                            print(f"Attempting match of {func_name} in {b} {cu_src} {decl_file}")
                            bincu_stats[b][cu_src]['total'] += 1
                            bin_func = bin_functions_by_file[b][cu_src][decl_file][func_name]
                            if func_name in src_bodies and decl_file == src_bodies[func_name]['file']:
                                bincu_stats[b][cu_src]['found'] += 1
                                src_func = src_bodies[func_name]
                                # Merge
                                bin_func['src_body'] = src_func['body']
                                comments = []
                                for fname, line, comment in src_func['comments']:
                                    fname = make_relative(fname, args.SOURCE_PATH)
                                    comments.append( (fname, line, comment) )
                                bin_func['src_comments'] = comments
                                bin_func['src_lines'] = [src_func['start'], src_func['end']]
                                bin_func['package'] = args.pkg_name
                                bin_func['decl_file'] = make_relative(decl_file, args.SOURCE_PATH)
                                bin_func['binary'] = make_relative(b, args.SOURCE_PATH)
                                print(json.dumps(bin_func), file=outfile)
            tm.end('get_source_bodies')

    outfile.close()

    # Print out stats about the binary/CU function matching
    print(f"Bin/CU stats:")
    grand_total = 0
    grand_found = 0
    headers = ['Binary', 'Compilation Unit', 'Found', 'Total']
    rows = []
    for b in bincu_stats:
        brel = make_relative(b, args.SOURCE_PATH)
        for cu in bincu_stats[b]:
            curel = make_relative(cu, args.SOURCE_PATH)
            found = bincu_stats[b][cu]['found']
            total = bincu_stats[b][cu]['total'] 
            grand_found += found
            grand_total += total
            rows.append( [brel, curel, found, total] )
    print(tabulate(rows, headers))
    print(f"Grand Total: {grand_found:5} / {grand_total:5}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['binary_comments', 'asm_source'], help='Which mode to run in.')
    parser.add_argument('compile_commands', default='compile_commands.json',
        type=str, help='compile_commands.json file')
    parser.add_argument('-o', '--output', default='output.json')
    parser.add_argument('-b', '--binary', required=False, action='append', help='Only work on this binary')
    args = parser.parse_args()

    if not os.path.exists(args.compile_commands):
        parser.error('No compile_commands.json found -- maybe you need to build the project with bear?')

    # Keep track of times taken
    tm = MiniTimer()
    args.tm = tm

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
    args.pkg_name = dir.relative_to(ROOT).parts[0]

    # Install build dependencies so that hopefully the environment
    # is very similar to the one used to compile the source files.
    tm.start('install_build_deps')
    if not os.path.exists('/tmp/builddeps_installed.stamp'):
        debs = find_build_deps(args.pkg_name)
        subprocess.run(['sudo', '-E', 'apt-get', '-y', 'update'])
        subprocess.run(['sudo', '-E', 'dpkg', '-i', '--force-all'] + debs)
        subprocess.run(['sudo', '-E', 'apt-get', '-y', '-f', 'install'])
        # Mark that we've done this so that we don't do it again.
        open('/tmp/builddeps_installed.stamp', 'w').close()
    tm.end('install_build_deps')

    # Both modes need the compile db
    # libclang wants it to be in a directory, so make one and symlink
    args.td = tempfile.mkdtemp()
    cc_path = os.path.abspath(args.compile_commands)
    # Add parse-all-comments to the command line for each arg
    # so that we get all the comments in the file.
    cc = json.load(open(cc_path))
    # for cmd in cc: cmd['arguments'].append('-fparse-all-comments')
    json.dump(cc, open(os.path.join(args.td, 'compile_commands.json'), 'w'))
    compdb = clang.cindex.CompilationDatabase.fromDirectory(args.td)

    # Copy the source files back to where they were at compile time
    tm.start('copy_source')
    src = ARCHIVE_PATH / args.pkg_name
    dest = ROOT / args.pkg_name
    if not dest.exists():
        dest.parent.mkdir(parents=True, exist_ok=True)
        print(f"Copying over source files from {src} to {dest}")
        subprocess.check_call(['cp', '-a', str(src), str(dest)])
    args.SOURCE_PATH = ROOT / args.pkg_name
    tm.end('copy_source')

    if args.mode == 'binary_comments':
        binary_comments(args)

    # Print timing info
    tm.print_totals()

    # Cleanup
    # Remove compile_commands.json
    os.unlink(os.path.join(args.td, 'compile_commands.json'))
    os.rmdir(args.td)

    sys.exit(0)

if __name__ == "__main__":
    main()

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
