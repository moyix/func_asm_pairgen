import os
import clang.cindex
from clang.cindex import Config, CursorKind, TokenKind, TranslationUnit, TranslationUnitLoadError
from bisect import bisect_right
from collections import defaultdict
from operator import itemgetter
import functools
import sys
from pathlib import Path
import IPython

n = os.path.normpath

# Manual path to the libclang.so.
LIBCLANG_PATH= '/usr/lib/llvm-14/lib/libclang-14.so.1'
Config.set_library_file(LIBCLANG_PATH)

def get_name(cursor):
    if hasattr(cursor, 'mangled_name'):
        return cursor.mangled_name
    else:
        return cursor.spelling

def preserve_cwd(function):
    @functools.wraps(function)
    def decorator(*args, **kwargs):
        cwd = os.getcwd()
        try:
            return function(*args, **kwargs)
        finally:
            os.chdir(cwd)
    return decorator

def is_cpp(args):
    if '++' in args[0]:
        return True
    if '-x' in args and '++' in args[args.index('-x')+1]:
        return True
    if any (x.endswith('.cpp') for x in args):
        return True
    return False

def remove_warnings(args):
    # Go through the args and remove any -W* flags EXCEPT for -Wl,*. We
    # iterate in reverse order so that we can remove items from the list
    # while iterating.
    for i in range(len(args)-1, -1, -1):
        if args[i].startswith('-W') and not args[i].startswith('-Wl,'):
            del args[i]
    return args

def is_pch(filename):
    return filename.endswith('.pch') or filename.endswith('.gch') or \
            (filename.endswith('.h') and os.path.exists(filename + '.gch'))

# Clean up an argument list from compile_commands.json into the form
# that libclang wants. For now just try to remove the source file name
# and "--".
def tidy_args(cmd):
    filename = cmd.filename
    if os.path.isabs(filename):
        relpath = os.path.relpath(filename, cmd.directory)
        abspath = filename
    else:
        abspath = os.path.join(cmd.directory, filename)
        relpath = filename

    args = list(cmd.arguments)

    args = [x for x in args if
            x != relpath and
            x != abspath and
            x != '-v' and
            x != '--']
    if not any(a.startswith('-std=') for a in args):
        if is_cpp(args):
            args.append('-std=c++17')
        else:
            args.append('-std=gnu17')

    # Remove warnings
    args = remove_warnings(args)

    # Remove any PCH files
    new_args = []
    for i in range(len(args)):
        if is_pch(args[i]):
            if new_args[i-1].startswith('-include'):
                del new_args[i-1]
            continue
        new_args.append(args[i])
    args = new_args

    args.insert(1, '-fparse-all-comments')
    return args

def try_parse(src, compdb):
    cmds = compdb.getCompileCommands(src)
    for cmd in cmds:
        os.chdir(cmd.directory)
        args = tidy_args(cmd)
        try:
            index = clang.cindex.Index.create()
            # print("Try parsing", src, "with:\n" + " ".join(args), file=sys.stderr)
            tu = index.parse(src, args)
            for diag in tu.diagnostics:
                if diag.severity >= 3:
                    print("WARNING: parse succeeded with errors:", diag.spelling, file=sys.stderr)
            return tu
        except TranslationUnitLoadError as e:
            print(f"WARNING: parse failed for {src}:", e, file=sys.stderr)
            continue

def header_parse(src):
    index = clang.cindex.Index.create()
    try:
        tu = index.parse(
            src,
            args=["-fparse-all-comments", "-fsyntax-only"],
            options=TranslationUnit.PARSE_INCOMPLETE,
        )
        return tu
    except TranslationUnitLoadError as e:
        print(f"WARNING: header parse failed for {src}:", e, file=sys.stderr)
        return None

# TODO: REMOVE THIS AS SOON AS WE ACTUALLY DO SOMETHING SMARTER WITH PICKING
#       OUT A COMPILATION COMMAND!
parsed_source_cache = {}

def iter_ast(cursor):
    yield cursor
    for child in cursor.get_children():
        yield from iter_ast(child)

# Wrap this with preserve_cwd so that we can change directory with
# impunity.
@preserve_cwd
def get_source_bodies(src, td):
    compdb = clang.cindex.CompilationDatabase.fromDirectory(td)
    source_bodies = {}
    if src in parsed_source_cache:
        return parsed_source_cache[src]
    tu = try_parse(src, compdb)
    if tu is None:
        parsed_source_cache[src] = source_bodies
        return source_bodies
    main_tu = tu
    function_defs = [ c for c in iter_ast(tu.cursor)
                        if c.kind == CursorKind.FUNCTION_DECL or
                        c.kind == CursorKind.CXX_METHOD
                    ]
    filemap = defaultdict(list)
    for f in function_defs:
        name = get_name(f)
        extent = f.extent
        if not name: continue
        filemap[n(extent.start.file.name)].append( (extent.start.line, extent.end.line, name) )
        if not f.is_definition(): continue
        #print(f"{f.spelling}: {extent.start.file.name} {extent.start.line}:{extent.start.column} - {extent.end.file.name} {extent.end.line}:{extent.end.column}")
        if extent.start.file.name != extent.end.file.name:
            continue
        try:
            lines = open(extent.start.file.name).readlines()
        except UnicodeDecodeError:
            lines = open(extent.start.file.name, encoding='latin1').readlines()
        body = lines[extent.start.line-1:extent.end.line]
        body[0] = body[0][extent.start.column-1:]
        body[-1] = body[-1][:extent.end.column]
        body = ''.join(body)
        if name in source_bodies:
            print("WARNING: Function already found in source_bodies:", name, extent.start.file.name, file=sys.stderr)
            continue
        source_bodies[name] = {}
        source_bodies[name]['body'] = body
        source_bodies[name]['file'] = n(extent.start.file.name)
        source_bodies[name]['start'] = extent.start.line
        source_bodies[name]['end'] = extent.end.line
        source_bodies[name]['comments'] = []

    filelines = {}
    for p in filemap:
        filemap[p].sort(key=itemgetter(0))
        filelines[p] = [x[0] for x in filemap[p]]
    # print(filemap)
    # print(filelines)

    # For the main src file, we have a high quality TU. For the headers,
    # just do a quick and dirty parse.
    all_tu = {}
    for p in filemap:
        if p == main_tu.spelling:
            all_tu[p] = main_tu
        else:
            htu = header_parse(p)
            if not htu: continue
            all_tu[p] = htu

    # Try to get all comments and associate them with the function.
    COMMENT_DISTANCE_THRESHOLD = 2 # If the comment is more than this many lines
                                   # away from the function, ignore it.
    for p, tu in all_tu.items():
        for t in tu.cursor.get_tokens():
            if t.kind == TokenKind.COMMENT:
                comment_file = n(t.extent.end.file.name)
                comment_line = t.extent.end.line
                comment_line_start = t.extent.start.line
                i = bisect_right(filelines[comment_file], comment_line) - 1
                # Either the comment is inside the function, or it is
                # within a few lines of the next function.
                if i >= 0:
                    f_start, f_end, f_name = filemap[comment_file][i]
                    if f_start <= comment_line <= f_end:
                        if f_name in source_bodies:
                            source_bodies[f_name]['comments'].append((comment_file, comment_line_start, t.spelling))
                        continue
                if 0 <= i+1 < len(filemap[comment_file]):
                    f_start, f_end, f_name = filemap[comment_file][i+1]
                    if abs(f_start - comment_line) <= COMMENT_DISTANCE_THRESHOLD:
                        if f_name in source_bodies:
                            source_bodies[f_name]['comments'].append((comment_file, comment_line_start, t.spelling))
    #IPython.embed(colors='neutral')
    parsed_source_cache[src] = source_bodies
    return source_bodies

if __name__ == "__main__":
    import sys, json
    print(json.dumps(get_source_bodies(sys.argv[2],sys.argv[1])))
