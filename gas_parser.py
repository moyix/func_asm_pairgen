#!/usr/bin/env python3
# Parse out functions from .s files

from calendar import c
import re

def set(d, dk, upd):
    if dk in d:
        d[dk].update(upd)
    else:
        d[dk] = upd

def update_data(syms, name, data):
    if name in syms and 'data' in syms[name]:
        syms[name]['data'].append(data)
    else:
        set(syms, name, {'data': [data]})

# 	.text
# 	.p2align 4
# 	.globl	compare_coeffs_with_index
# 	.type	compare_coeffs_with_index, @function
# compare_coeffs_with_index:
# .LFB39:
# 	.cfi_startproc
# 	movss	4(%rdi), %xmm1
#   [...]
#   negl	%eax
# .L1:
# 	ret
# 	.cfi_endproc
# .LFE39:
# 	.size	compare_coeffs_with_index, .-compare_coeffs_with_index
# 	.p2align 4

# 	.file	"metapixel.c"
#   .file 0 "./build/workspaces/gcc" "../../../source/network/StunClient.cpp"
FILE_DECL = re.compile(r'\.file\s+(\d+)?(?:\s+)?"([^"]+)"(?:\s+)?(?:"([^"]+)")?(?:\s+)?([0-9A-Fa-f]+)?')
GLOBAL_SYM = re.compile(r'\.globa?l\s+([^\s]+)')
ALIGN = re.compile(r'\.(p2)?align\s+(\d+)')
TEXT_SECTION = re.compile(r'\.text')
DATA_SECTION = re.compile(r'\.data')
BSS_SECTION = re.compile(r'\.bss')
SECTION = re.compile(r'\.section\s+([^,]+),?\s*([^,]*),?\s*([^,]*),?\s*([^,]*)')
LABELDEF = re.compile(r'([^:\s]+):')
IDENT = re.compile(r'\.ident\s+([^\s].*)')
# Strings. Have to be a bit careful with escaped quotes
STRINGDEF = re.compile(r'\.string(?:8|16|32)?\s+"((?:[^"\\]|\\.)*)"')
ASCIIDEF = re.compile(r'\.ascii\s+"((?:[^"\\]|\\.)*)"')
ASCIZDEF = re.compile(r'\.asciz\s+"((?:[^"\\]|\\.)*)"')
# Type decl. gas manual says it supports:
#   .type name STT_OBJECT
#   .type name, #object
#   .type name, @object
#   .type name, %object
#   .type name, "object"
STT_TYPEDEF = re.compile(r'\.type\s+([^\s]+)\s+(STT_[A-Z_]+)')
STT_NAME_MAP = {
    "STT_FUNC":      "function",
    "STT_GNU_IFUNC": "gnu_indirect_function",
    "STT_OBJECT":    "object",
    "STT_TLS":       "tls_object",
    "STT_COMMON":    "common",
    "STT_NOTYPE":    "notype",
}
TYPEDEF = re.compile(r'\.type\s+([^,]+),\s*[#@%"]([^#@%"]+)"?')                                                                  
SYM_SIZE = re.compile(r'\.size\s+([^,]+),\s+([^\s]+)')
LOCALDEF = re.compile(r'\.local\s+([^\s].*)')
WEAKDEF = re.compile(r'\.weak\s+([^\s].*)')
WEAKREF = re.compile(r'\.weakref\s+([^,]+),\s*([^\s]+)')
HIDDENDEF = re.compile(r'\.hidden\s+([^\s].*)')
COMMDEF = re.compile(r'\.comm\s+([^,]+),\s*(\d+)(?:,\s*(\d+))?')
INT_CONST = re.compile(r'.(?:long|int)\s+(-?\d+)')
INT_LABEL = re.compile(r'.(?:long|int)\s+([^\s]+)')
QUAD_CONST = re.compile(r'.quad\s+(-?\d+)')
QUAD_LABEL = re.compile(r'\.quad\s+([^\s]+)')
ZERO = re.compile(r'\.zero\s+(\d+)')
BYTE = re.compile(r'\.byte\s+(-?0x[0-9A-Fa-f]+|-?\d+)')
BYTE_LABEL = re.compile(r'\.byte\s+([^\s]+)')
VALUE = re.compile(r'\.value\s+(-?0x[0-9A-Fa-f]+|-?\d+)')
VALUE_LABEL = re.compile(r'\.value\s+([^\s]+)')
ULEB128 = re.compile(r'\.uleb128\s+([^\s].*)')
SLEB128 = re.compile(r'\.sleb128\s+([^\s].*)')
SET = re.compile(r'\.set\s+([^,]+),\s*([^\s].*)')
# Example sections
SECTION_TEST_DATA = """
.section        .data.rel.local,"aw"
.section        .data.rel.ro.local,"aw"
.section        .note.GNU-stack,"",@progbits
.section        .rodata
.section        .rodata.cst16,"aM",@progbits,16
.section        .rodata.cst4
.section        .rodata.cst4,"aM",@progbits,4
.section        .rodata.cst8,"aM",@progbits,8
.section        .rodata.str1.1
.section        .rodata.str1.1,"aMS",@progbits,1
.section        .rodata.str1.8
.section        .rodata.str1.8,"aMS",@progbits,1
.section        .text.startup
.section        .text.startup,"ax",@progbits
"""
def test_sections():
    for line in SECTION_TEST_DATA.splitlines():
        if not line:
            continue
        m = SECTION.match(line)
        assert(m)

def parse_asm(asm_file):
    asm = {}
    asm['functions'] = {}
    asm['globals'] = []
    asm['sections'] = {}
    asm['symbols'] = {}
    current_section = None
    current_label = None
    current_function = None
    func_body = False
    line_no = 0
    for line in asm_file:
        line_no += 1
        line = line.strip()
        if not line: continue
        # print("DEBUG:", line)
        m = FILE_DECL.match(line)
        if m:
            parts = m.groups()
            partslen = len([p for p in parts if p])
            file = {}
            if partslen == 1:
                file['file'] = parts[1]
                file['file_id'] = None
                file['directory'] = None
                file['md5'] = None
            elif partslen >= 2: # dwarf2 or dwarf5 format
                file['file_id'] = parts[0]
                file['file'] = parts[1]
                file['directory'] = parts[2]
                file['md5'] = parts[3]
            if current_label:
                set(asm['symbols'], current_label, file)
            else:
                asm.update(file)
            continue
        m = IDENT.match(line)
        if m:
            ident = m.group(1)
            asm['ident'] = ident
            continue
        m = GLOBAL_SYM.match(line)
        if m:
            global_name = m.group(1)
            set(asm['symbols'], global_name, {'visibility': 'global'}) 
            asm['globals'].append(global_name)
            continue
        m = STT_TYPEDEF.match(line) or TYPEDEF.match(line)
        if m:
            sym_name = m.group(1)
            sym_type = m.group(2)
            if sym_type.startswith('STT_'):
                sym_type = STT_NAME_MAP[sym_type]
            set(asm['symbols'], sym_name, {'type': sym_type}) 
            if sym_type == 'function':
                current_function = sym_name
                set(asm['functions'], current_function, {'body': [], 'labels': []})
                func_body = True
            continue
        m = SYM_SIZE.match(line)
        if m:
            sym_name = m.group(1)
            sym_size = m.group(2)
            set(asm['symbols'], sym_name, {'size': sym_size})
            continue
        m = LABELDEF.match(line)
        if m:
            label = m.group(1)
            current_label = label
            if func_body:
                # Include labels in the function body
                asm['functions'][current_function]['body'].append(line)
                asm['functions'][current_function]['labels'].append(label)
            set(asm['symbols'], label, {'has_label': True})
            if label.startswith('.LFE'):
                func_body = False
            continue
        m = LOCALDEF.match(line)
        if m:
            local = m.group(1)
            local = local.split(',')
            for l in local:
                set(asm['symbols'], l, {'visibility': 'local'}) 
            continue
        m = WEAKREF.match(line)
        if m:
            weak = m.group(1)
            target = m.group(2)
            set(asm['symbols'], weak, {'target': target, 'weak': True})
            continue
        m = WEAKDEF.match(line)
        if m:
            weak = m.group(1)
            for w in weak:
                set(asm['symbols'], w, {'weak': True}) 
            continue
        m = HIDDENDEF.match(line)
        if m:
            hidden = m.group(1)
            hidden = hidden.split(',')
            for h in hidden:
                set(asm['symbols'], h, {'visibility': 'hidden'})
            continue

        m = COMMDEF.match(line)
        if m:
            comm = m.group(1)
            size = m.group(2)
            align = m.group(3)
            if align is None:
                align = 1
            else:
                align = int(align)
            set(asm['symbols'], comm, {'size': size, 'align': align})
            continue
        m = SET.match(line)
        if m:
            sym_name = m.group(1)
            sym_value = m.group(2)
            set(asm['symbols'], sym_name, {'value': sym_value})
            continue

        # Data
        dtype = None
        value = None
        m = INT_LABEL.match(line)
        if m:
            dtype = 'int_label'
            value = m.group(1)
        m = INT_CONST.match(line)
        if m:
            dtype = 'int'
            value = int(m.group(1))
        m = QUAD_LABEL.match(line)
        if m:
            dtype = 'quad_label'
            value = m.group(1)
        m = QUAD_CONST.match(line)
        if m:
            dtype = 'quad'
            value = int(m.group(1))
        m = STRINGDEF.match(line) or ASCIIDEF.match(line) or ASCIZDEF.match(line)
        if m:
            dtype = 'string'
            value = m.group(1)
        m = ZERO.match(line)
        if m:
            dtype = 'zero'
            value = int(m.group(1))
        m = BYTE_LABEL.match(line)
        if m:
            dtype = 'byte_label'
            value = m.group(1)
        m = BYTE.match(line)
        if m:
            dtype = 'byte'
            value = int(m.group(1), 0)
        m = VALUE_LABEL.match(line)
        if m:
            dtype = 'value_label'
            value = m.group(1)
        m = VALUE.match(line)
        if m:
            dtype = 'value'
            value = int(m.group(1), 0)
        m = ULEB128.match(line)
        if m:
            dtype = 'uleb128'
            value = m.group(1)
        m = SLEB128.match(line)
        if m:
            dtype = 'sleb128'
            value = m.group(1)
        if dtype is not None:
            update_data(asm['symbols'], current_label, (dtype, value))
            continue

        # Section handling
        section_name = None
        section_flags = None
        section_type = None
        section_entsize = None
        m = TEXT_SECTION.match(line)
        if m:
            section_name = 'text'
        m = DATA_SECTION.match(line)
        if m:
            section_name = 'data'
        m = BSS_SECTION.match(line)
        if m:
            section_name = 'bss'
        m = SECTION.match(line)
        if m:
            section_args = [g for g in m.groups() if g]
            if section_args:
                section_name = section_args.pop(0)
            if section_args:
                section_flags = section_args.pop(0)
            if section_args:
                section_type = section_args.pop(0)
            if section_args:
                section_entsize = section_args.pop(0)
        if section_name:
            if current_section is not None:
                asm['sections'][current_section]['ranges'][-1][1] = line_no
            current_section = section_name
            if current_section not in asm['sections']:
                asm['sections'][current_section] = {}
                asm['sections'][current_section]['flags'] = section_flags
                asm['sections'][current_section]['type'] = section_type
                asm['sections'][current_section]['entsize'] = section_entsize
                asm['sections'][current_section]['ranges'] = [[line_no, line_no]]
            else:
                asm['sections'][current_section]['ranges'].append([line_no, line_no])
            continue

        if func_body:
            # We don't try to parse stuff inside of function bodies
            asm['functions'][current_function]['body'].append(line)
            continue
        
        # Stuff we don't care about
        for regex in [ALIGN]:
            if regex.match(line):
                break
        else:
            print(f"WARNING: {asm_file.name}:{line_no} : Unhandled line: {line}", file=sys.stderr)
            continue
            #raise Exception(f"{asm_file.name}:{line_no} : Unhandled line: {line}")

    # Close the range of the last section
    asm['sections'][current_section]['ranges'][-1][1] = line_no

    return asm

if __name__ == "__main__":
    import sys
    import json
    with open(sys.argv[1], "r") as f:
        asm = parse_asm(f)
        #print(json.dumps(asm, indent=2, sort_keys=True))
