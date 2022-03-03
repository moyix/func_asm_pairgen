from pathlib import Path

ASMDIR = Path("/fastdata2/debian_allsrc/asm")
LLVMIRDIR = Path("/fastdata2/debian_allsrc/llvm-ir")

BLACKLISTED_EXTENSIONS = { '.h', '.gch' }

def asm_ignore_file(command):
    if any(command['file'].endswith(ext) for ext in BLACKLISTED_EXTENSIONS):
        return True
    if 'output'in command and any(command['output'].endswith(ext) for ext in BLACKLISTED_EXTENSIONS):
        return True
    args = command['arguments']
    for i in range(len(command['arguments'])):
        if args[i] == '-x':
            lang = args[i+1]
            if lang == 'c-header' or lang == 'c++-header':
                return True
    return False

def generate_asm(command, filename, pkg_name):
    if asm_ignore_file(command): return None

    # This is where we'll put the ASM output
    asm_path = ASMDIR / pkg_name
    asm_dest = (asm_path/filename).with_suffix(".s")
    args = command["arguments"][:]

    if 'output' in command:
        for i,arg in enumerate(args):
            if arg == "-c":
                args[i] = "-S"
            if arg == "-o":
                args[i+1] = str(asm_dest)
    else:
        args.append("-S")
        args += ['-o', (str(asm_dest))]
    cmd_dir = Path(command['directory'])
    return ('ASM', str(cmd_dir), filename, args, str(asm_dest))

def generate_llvm(command, filename, pkg_name):
    if asm_ignore_file(command): return None

    # This is where we'll put the LLVM output
    llvm_path = LLVMIRDIR / pkg_name

    llvm_dest = (llvm_path/filename).with_suffix(".bc")
    llvm_dest.parent.mkdir(parents=True, exist_ok=True)
    args = command["arguments"][:]

    if 'output' in command:
        for i,arg in enumerate(args):
            if arg == "-o":
                args[i+1] = str(llvm_dest)
        # Still have to put the -emit-llvm flag in
        args.append("-emit-llvm")
    else:
        args.append("-emit-llvm")
        args += ['-o', (str(llvm_dest))]
    cmd_dir = Path(command['directory'])
    return ('LLVM-IR', str(cmd_dir), filename, args, str(llvm_dest))

HANDLERS = [generate_asm, generate_llvm]

def gen_command_list(database, root, pkg_name):
    commands_to_run = []
    for command in database:
        try:
            filename = Path(command["file"]).relative_to(root / pkg_name)
        except ValueError:
            # Source file is outside the package, skip it
            continue

        for handler in HANDLERS:
            cmd = handler(command, filename)
            if cmd:
                commands_to_run.append(cmd)

    # Deduplicate any output files that are the same
    seen_outputs = set()
    for i in range(len(commands_to_run)):
        cmd = commands_to_run[i]
        args = cmd[3]
        output = cmd[4]
        if output in seen_outputs:
            j = args.index(output)
            new_output = f"{output}.{i}"
            args[j] = new_output
            commands_to_run[i] = (cmd[0], cmd[1], cmd[2], args, new_output)
            print(f"Duplicate output file {output} => {new_output}")
        else:
            seen_outputs.add(cmd[4])
