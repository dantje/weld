#!/usr/bin/env python3
"""Tests of the linker.

  python3 tests/test.py [--fuzz N] [files...]

Builds src/weld.goose with the goose on PATH (or $GOOSE), then checks that
`weld dump` prints exactly what `readelf -sW` prints for each file (by
default the system's libc.a and libstdc++.a, and when goose is run from a
build of it, the objects in its build tree); that `ld resolve` takes the same archive
members as GNU ld for a static hello world, and reports duplicate and
undefined symbols; that freestanding, static glibc and static C++ programs it links run, with
one copy of each COMDAT group; that a shared library it links runs; that
its XXH3 is libxxhash's, and its build IDs follow the output's bytes alone;
and that N corrupted objects and archives (default 1000) are each read or
rejected with a message, never aborted on.
"""
import argparse, ctypes, ctypes.util, glob, os, random, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))       # tests/
ROOT = os.path.dirname(HERE)                              # weld's checkout
GOOSE = os.environ.get('GOOSE') or shutil.which('goose') or sys.exit('goose not found: put it on PATH or set GOOSE')


def build(out_dir):
    exe = os.path.join(out_dir, 'weld')
    r = subprocess.run([GOOSE, 'build', os.path.join(ROOT, 'src', 'weld.goose'), '-o', exe],
                       capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(r.stdout + r.stderr)
    return exe


def compare_readelf(exe, files):
    failed = 0
    for f in files:
        ours = subprocess.run([exe, 'dump', f], capture_output=True).stdout
        theirs = subprocess.run(['readelf', '-sW', f], capture_output=True).stdout
        if ours != theirs:
            failed += 1
            print('FAIL readelf -sW differs:', f)
    print(f'readelf: {len(files) - failed}/{len(files)} identical')
    return failed


def members_in_map(path):
    """The archive members a GNU ld map says the link took, as (archive, member)."""
    taken, inside = set(), False
    for line in open(path):
        if line.startswith('Archive member included'):
            inside = True
        elif line.startswith('Discarded input sections'):
            break
        elif inside and line[:1] not in ('', ' ', '\n'):
            name = line.split()[0]
            if name.endswith(')') and '(' in name:
                archive, member = name[:-1].split('(', 1)
                taken.add((os.path.basename(archive), member))
    return taken


def check_resolve(exe, work):
    failed = 0
    src = os.path.join(work, 'hello.c')
    open(src, 'w').write('#include <stdio.h>\nint main(void) { printf("hi %d\\n", 42); return 0; }\n')
    obj = os.path.join(work, 'hello.o')
    subprocess.run(['gcc', '-O2', '-c', src, '-o', obj], check=True)
    linkmap = os.path.join(work, 'hello.map')
    r = subprocess.run(['gcc', '-static', '-v', obj, '-o', os.path.join(work, 'hello'), '-Wl,-Map=' + linkmap],
                       capture_output=True, text=True, check=True)
    argv = next(l for l in r.stderr.splitlines() if 'collect2' in l).split()[1:]
    r = subprocess.run([exe, 'resolve', '--trace'] + argv, capture_output=True, text=True)
    ours = set()
    for line in r.stdout.splitlines():
        if line.endswith(')') and '(' in line:
            archive, member = line[:-1].split('(', 1)
            ours.add((os.path.basename(archive), member))
    theirs = members_in_map(linkmap)
    if r.returncode != 0 or ours != theirs:
        failed += 1
        print('FAIL resolve: static hello takes different members than GNU ld')
        print('  only ours:', sorted(ours - theirs)[:10], ' only GNU ld:', sorted(theirs - ours)[:10])
        print(r.stdout[-500:])
    a, b = os.path.join(work, 'a.c'), os.path.join(work, 'b.c')
    open(a, 'w').write('int twice(void) { return 2; }\n')
    open(b, 'w').write('int twice(void) { return 3; }\nextern int missing(void);\nint use(void) { return missing(); }\n')
    subprocess.run(['gcc', '-c', a, b], cwd=work, check=True)
    r = subprocess.run([exe, 'resolve', os.path.join(work, 'a.o'), os.path.join(work, 'b.o')], capture_output=True, text=True)
    if r.returncode != 1 or 'duplicate symbol: twice' not in r.stdout or 'undefined symbol: missing' not in r.stdout:
        failed += 1
        print('FAIL resolve: duplicate or undefined symbol not reported\n' + r.stdout)
    # Dynamically: libc.so is a script naming libc.so.6, libc_nonshared.a and ld.so.
    linkmap = os.path.join(work, 'hello_dyn.map')
    r = subprocess.run(['gcc', '-v', obj, '-o', os.path.join(work, 'hello_dyn'), '-Wl,-Map=' + linkmap],
                       capture_output=True, text=True, check=True)
    argv = next(l for l in r.stderr.splitlines() if 'collect2' in l).split()[1:]
    r = subprocess.run([exe, 'resolve', '--trace'] + argv, capture_output=True, text=True)
    dyn = set()
    for line in r.stdout.splitlines():
        if line.endswith(')') and '(' in line:
            archive, member = line[:-1].split('(', 1)
            dyn.add((os.path.basename(archive), member))
    if r.returncode != 0 or dyn != members_in_map(linkmap):
        failed += 1
        print('FAIL resolve: dynamic hello\n' + r.stdout[-500:])
    print(f'resolve: {len(ours)} members as GNU ld; dynamically, {len(dyn)}' if not failed else 'resolve: failed')
    return failed


def check_freestanding(exe, work):
    """Links test/start.c and test/lib.c (from an archive) with no C library and runs the result."""
    flags = ['-O2', '-fno-pie', '-fno-stack-protector', '-fcommon', '-ffreestanding', '-c']
    for name in ('start', 'lib'):
        subprocess.run(['gcc'] + flags + [os.path.join(HERE, 'data', name + '.c'), '-o', os.path.join(work, name + '.o')], check=True)
    archive = os.path.join(work, 'libfree.a')
    subprocess.run(['ar', 'rcs', archive, os.path.join(work, 'lib.o')], check=True)
    out = os.path.join(work, 'free')
    r = subprocess.run([exe, 'link', '-o', out, os.path.join(work, 'start.o'), archive], capture_output=True, text=True)
    if r.returncode != 0:
        print('FAIL link: freestanding program did not link\n' + r.stdout)
        return 1
    run = subprocess.run([out], capture_output=True, text=True)
    if run.returncode != 42 or run.stdout != 'hello from a Goose-linked program\n':
        print(f'FAIL link: freestanding program exited {run.returncode} with {run.stdout!r}')
        return 1
    print('link: freestanding program runs')
    return 0


def symbols(path):
    """A symbol table's functions, IFUNCs, TLS symbols and global objects, as
    (name, type, binding, visibility, size): what does not depend on layout."""
    out = set()
    for line in subprocess.run(['readelf', '-sW', path], capture_output=True, text=True).stdout.splitlines():
        f = line.split()
        if len(f) == 8 and f[0].endswith(':') and f[6] != 'UND':
            if f[3] in ('FUNC', 'IFUNC', 'TLS') or (f[3] == 'OBJECT' and f[4] != 'LOCAL'):
                out.add((f[7], f[3], f[4], f[5], f[2]))
    return out


def notes(path):
    """The property note's line and the build ID's length, as readelf shows them."""
    text = subprocess.run(['readelf', '-nW', path], capture_output=True, text=True).stdout
    prop = next((l.split('Properties:')[1].strip() for l in text.splitlines() if 'Properties:' in l), '')
    bid = next((l.split('Build ID:')[1].strip() for l in text.splitlines() if 'Build ID:' in l), '')
    return prop, len(bid) // 2


def check_eh_frame_hdr(path):
    """Whether .eh_frame_hdr lists each FDE of code once, sorted, pointing at it; what is wrong if not."""
    import re, struct
    secs = {}
    for line in subprocess.run(['readelf', '-SW', path], capture_output=True, text=True).stdout.splitlines():
        m = re.match(r'\s*\[\s*\d+\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)', line)
        if m:
            secs[m.group(1)] = (int(m.group(2), 16), int(m.group(3), 16), int(m.group(4), 16))
    if '.eh_frame_hdr' not in secs:
        return 'no .eh_frame_hdr'
    data = open(path, 'rb').read()
    haddr, hoff, _ = secs['.eh_frame_hdr']
    eaddr = secs['.eh_frame'][0]
    lo = min(secs[n][0] for n in ('.init', '.text') if n in secs)
    hi = max(secs[n][0] + secs[n][2] for n in ('.text', '.iplt', '.fini') if n in secs)
    if tuple(data[hoff:hoff + 4]) != (1, 0x1b, 0x03, 0x3b):
        return 'bad header'
    ptr, count = struct.unpack_from('<iI', data, hoff + 4)
    if haddr + 4 + ptr != eaddr:
        return 'bad .eh_frame pointer'
    table = [struct.unpack_from('<ii', data, hoff + 12 + 8 * i) for i in range(count)]
    ours = [(haddr + pc, haddr + fde) for pc, fde in table]
    want = set()
    for line in subprocess.run(['readelf', '--debug-dump=frames', path], capture_output=True, text=True).stdout.splitlines():
        m = re.match(r'([0-9a-f]+) [0-9a-f]+ [0-9a-f]+ FDE cie=[0-9a-f]+ pc=([0-9a-f]+)\.\.', line)
        if m and lo <= int(m.group(2), 16) < hi:
            want.add((int(m.group(2), 16), eaddr + int(m.group(1), 16)))
    if ours != sorted(ours) or set(ours) != want:
        return f'{count} entries, {len(want)} FDEs of code'
    return ''


def eh_frame_problems(path):
    """Whether .eh_frame's records run whole to its end, a zero length (the
    terminator) only last, each FDE's CIE pointer at a CIE and no FDE of code
    at 0, as left-out code would be; what is wrong if not."""
    import re, struct
    for line in subprocess.run(['readelf', '-SW', path], capture_output=True, text=True).stdout.splitlines():
        m = re.match(r'\s*\[\s*\d+\]\s+\.eh_frame\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)', line)
        if m:
            addr, off, size = (int(g, 16) for g in m.groups())
            break
    else:
        return 'no .eh_frame'
    b = open(path, 'rb').read()[off:off + size]
    pos, cies, fdes = 0, set(), 0
    while pos + 4 <= len(b):
        length = struct.unpack_from('<I', b, pos)[0]
        if length == 0:
            if pos + 4 != len(b):
                return f'a zero length at {pos:#x} of {len(b):#x}, which ends the table early'
            break
        if pos + 4 + length > len(b) or length < 8:
            return f'a record at {pos:#x} runs past the end'
        cie = struct.unpack_from('<I', b, pos + 4)[0]
        if cie == 0:
            cies.add(pos)
        else:
            fdes += 1
            if pos + 4 - cie not in cies:
                return f'the FDE at {pos:#x} points at no CIE'
            if struct.unpack_from('<i', b, pos + 8)[0] + addr + pos + 8 == 0:
                return f'the FDE at {pos:#x} is of code at 0'
        pos += 4 + length
    return ''


def check_static(exe, work):
    """Links static C and C++ programs from gcc's own command lines, glibc and libstdc++
    included, and checks that they run as GNU ld's links of them do."""
    failed = 0
    programs = [('hello.c', 'gcc', '#include <stdio.h>\nint main(void) { printf("hi %d\\n", 42); return 0; }\n'),
                ('exc.cpp', 'g++', '#include <cstdio>\n#include <stdexcept>\n'
                 'int main(int c, char **) { try { if (c > 0) throw std::runtime_error("boom"); }\n'
                 ' catch (const std::exception &e) { std::printf("caught %s\\n", e.what()); return 3; } return 0; }\n')]
    for name, cc, text in programs:
        src = os.path.join(work, name)
        open(src, 'w').write(text)
        obj = src + '.o'
        subprocess.run([cc, '-O2', '-c', src, '-o', obj], check=True)
        gnu = src + '.gnu'
        r = subprocess.run([cc, '-static', '-v', obj, '-o', gnu], capture_output=True, text=True, check=True)
        argv = next(l for l in r.stderr.splitlines() if 'collect2' in l).split()[1:]
        k = argv.index('-o')
        ours = src + '.ours'
        argv[k + 1] = ours
        r = subprocess.run([exe, 'link'] + argv, capture_output=True, text=True)
        if r.returncode != 0:
            failed += 1
            print(f'FAIL link: static {name} did not link\n' + r.stdout[-1000:])
            continue
        if notes(ours) != notes(gnu):
            failed += 1
            print(f'FAIL link: static {name}: notes {notes(ours)}, GNU ld\'s {notes(gnu)}')
        if name.endswith('.cpp'):         # gcc asks for no .eh_frame_hdr when static; ask for one
            hdr = ours + '.hdr'
            argv[argv.index('-o') + 1] = hdr
            r = subprocess.run([exe, 'link', '--eh-frame-hdr'] + argv, capture_output=True, text=True)
            argv[argv.index('-o') + 1] = ours
            wrong = check_eh_frame_hdr(hdr) if r.returncode == 0 else 'did not link'
            run = subprocess.run([hdr], capture_output=True, text=True) if not wrong else None
            if wrong or run.returncode != 3:
                failed += 1
                print(f'FAIL link: static {name} with --eh-frame-hdr: {wrong or run.stdout}')
        missing = symbols(gnu) - symbols(ours)
        if missing:
            failed += 1
            print(f'FAIL link: static {name}: {len(missing)} symbols GNU ld lists are missing or differ:', sorted(missing)[:5])
        want = subprocess.run([gnu], capture_output=True, text=True)
        got = subprocess.run([ours], capture_output=True, text=True)
        if (got.returncode, got.stdout) != (want.returncode, want.stdout):
            failed += 1
            print(f'FAIL link: static {name} exited {got.returncode} with {got.stdout!r}, '
                  f'GNU ld\'s {want.returncode} with {want.stdout!r}')
    if not failed:
        print('link: static C (glibc) and C++ (libstdc++, exceptions) programs run as with GNU ld, '
              'their symbol tables, property notes and build IDs as GNU ld\'s, .eh_frame_hdr complete')
    return failed


def check_comdat(exe, work):
    """Links test/comdat: eight C++ units instantiating the same templates and an inline
    function with a static local. Only one copy of each group may be kept, and every
    reference must reach it, or the program's counter splits and it exits 1."""
    src = os.path.join(HERE, 'data', 'comdat')
    objs = []
    for name in sorted(os.listdir(src)):
        if name.endswith('.cpp'):
            obj = os.path.join(work, 'comdat_' + name[:-4] + '.o')
            subprocess.run(['g++', '-O1', '-c', os.path.join(src, name), '-o', obj], check=True)
            objs.append(obj)
    gnu = os.path.join(work, 'comdat.gnu')
    r = subprocess.run(['g++', '-static', '-v'] + objs + ['-o', gnu], capture_output=True, text=True, check=True)
    argv = next(l for l in r.stderr.splitlines() if 'collect2' in l).split()[1:]
    ours = os.path.join(work, 'comdat.ours')
    argv[argv.index('-o') + 1] = ours
    r = subprocess.run([exe, 'link'] + argv, capture_output=True, text=True)
    run = subprocess.run([ours], capture_output=True, text=True) if r.returncode == 0 else None
    if run is None or run.returncode != 0 or 'calls 8' not in run.stdout or 'left out' not in r.stdout:
        print('FAIL link: COMDAT program\n' + r.stdout[-1000:] + (run.stdout if run else ''))
        return 1
    first = open(ours, 'rb').read()
    for k in range(8):           # symbols arrive at their shards in a different order each time,
        threads = [] if k < 4 else [f'--threads={k - 3}']      # and come from 1 to 4 workers
        subprocess.run([exe, 'link'] + threads + argv, capture_output=True, check=True)
        if open(ours, 'rb').read() != first:
            print('FAIL link: COMDAT program differs from one link to the next' + (f' with {threads[0]}' if threads else ''))
            return 1
    wrong = eh_frame_problems(ours)
    if wrong:
        print('FAIL link: COMDAT program: .eh_frame:', wrong)
        return 1
    print('link: one copy of each COMDAT group kept, and the FDEs of the others left out; ' + run.stdout.strip() +
          '; the same bytes on 9 links, 1 to 4 threads')
    return 0


def dynamic_symbols(path):
    """A shared library's dynamic symbols: name, type, binding, visibility, section or UND."""
    out = set()
    for line in subprocess.run(['readelf', '--dyn-syms', '-W', path], capture_output=True, text=True).stdout.splitlines():
        f = line.split()
        if len(f) >= 8 and f[0].endswith(':'):
            out.add((f[7], f[3], f[4], f[5], 'UND' if f[6] == 'UND' else 'defined'))
    return out


def needed(path):
    text = subprocess.run(['readelf', '-dW', path], capture_output=True, text=True).stdout
    return [l.split('[')[1].rstrip(']') for l in text.splitlines() if '(NEEDED)' in l]


def check_shared(exe, work):
    """Links test/shlib/demo.c into a shared library, as gcc -shared would have GNU ld link it,
    and runs a program GNU ld links against it: exported functions and data, PLT calls,
    run-time relocations, TLS and a constructor. Its dynamic symbols and DT_NEEDED must be
    GNU ld's."""
    src = os.path.join(HERE, 'data', 'shlib')
    d = os.path.join(work, 'shlib')
    os.makedirs(d, exist_ok=True)
    obj = os.path.join(d, 'demo.o')
    subprocess.run(['gcc', '-O2', '-g', '-fPIC', '-c', os.path.join(src, 'demo.c'), '-o', obj], check=True)
    gnu = os.path.join(d, 'libdemo.gnu.so')
    r = subprocess.run(['gcc', '-shared', '-v', obj, '-o', gnu, '-Wl,-soname,libdemo.so', '-Wl,-z,now'],
                       capture_output=True, text=True, check=True)
    argv = next(l for l in r.stderr.splitlines() if 'collect2' in l).split()[1:]
    ours = os.path.join(d, 'libdemo.so')
    argv[argv.index('-o') + 1] = ours
    r = subprocess.run([exe, 'link'] + argv, capture_output=True, text=True)
    if r.returncode != 0:
        print('FAIL link: shared library did not link\n' + r.stdout[-1000:])
        return 1
    main = os.path.join(d, 'main')
    subprocess.run(['gcc', '-O2', os.path.join(src, 'main.c'), '-L' + d, '-ldemo', '-o', main], check=True)
    run = subprocess.run([main], capture_output=True, text=True, env=dict(os.environ, LD_LIBRARY_PATH=d))
    failed = 0
    if run.returncode != 0 or 'counter 42; sum 35, calls 3' not in run.stdout:
        failed += 1
        print(f'FAIL link: program using our shared library exited {run.returncode}: {run.stdout!r} {run.stderr[-300:]!r}')
    if dynamic_symbols(ours) != dynamic_symbols(gnu) or needed(ours) != needed(gnu):
        failed += 1
        print('FAIL link: shared library: dynamic symbols or DT_NEEDED differ from GNU ld\'s:',
              sorted(dynamic_symbols(ours) ^ dynamic_symbols(gnu))[:6], needed(ours), needed(gnu))
    # Its debugging information: what a DWARF verifier finds, and where gdb
    # puts a function, as with GNU ld's link (gcc's own output has a finding).
    def dwarf(path):
        if not shutil.which('llvm-dwarfdump-22'):
            return None
        r = subprocess.run(['llvm-dwarfdump-22', '--verify', path], capture_output=True, text=True)
        return sorted(l for l in r.stdout.splitlines() if 'occurred' in l or l.startswith('No errors'))
    def line(path):
        r = subprocess.run(['gdb', '-q', '-batch', '-ex', 'info line demo_add', path], capture_output=True, text=True,
                           env=dict(os.environ, DEBUGINFOD_URLS=''))
        return r.stdout.split(' starts at')[0]          # "Line 19 of ...", without the address
    wrong = eh_frame_problems(ours)
    if wrong:
        failed += 1
        print('FAIL link: shared library: .eh_frame:', wrong)
    if dwarf(ours) != dwarf(gnu) or (shutil.which('gdb') and line(ours) != line(gnu)):
        failed += 1
        print('FAIL link: shared library: debugging information differs from GNU ld\'s:', dwarf(ours), dwarf(gnu))
    if not failed:
        print('link: a shared library runs, its dynamic symbols, DT_NEEDED and debugging information as GNU ld\'s')
    return failed


def check_as_ld(exe, work):
    """weld as a compiler driver runs a linker: as ld.weld, given ld's arguments
    alone (clang -fuse-ld=), quiet on success, writing --dependency-file."""
    clang = shutil.which('clang-22') or shutil.which('clang')
    if not clang:
        print('as ld: not checked: no clang')
        return 0
    d = os.path.join(work, 'as_ld')
    os.makedirs(d, exist_ok=True)
    ld = os.path.join(d, 'ld.weld')
    if not os.path.exists(ld):
        os.symlink(exe, ld)
    src = os.path.join(d, 'hi.c')
    open(src, 'w').write('#include <stdio.h>\n#include <math.h>\n'
                         'int main(void) { printf("%.3f\\n", sqrt(2.0)); return 0; }\n')
    out, dep = os.path.join(d, 'hi'), os.path.join(d, 'hi.d')
    r = subprocess.run([clang, '-O2', '-fuse-ld=' + ld, '-Wl,--dependency-file=' + dep, src, '-lm', '-o', out],
                       capture_output=True, text=True)
    run = subprocess.run([out], capture_output=True, text=True) if r.returncode == 0 else None
    deps = open(dep).read() if os.path.exists(dep) else ''
    if run is None or run.stdout != '1.414\n' or r.stdout or not deps.startswith(out + ':') or 'libc.so' not in deps:
        print('FAIL as ld: clang -fuse-ld=ld.weld:', r.returncode, r.stdout[-300:], r.stderr[-300:], deps[:200])
        return 1
    # A response file as clang writes one for a long command line: quoted.
    rsp = os.path.join(d, 'quoted.rsp')
    obj = os.path.join(d, 'hi.o')
    subprocess.run([clang, '-O2', '-c', src, '-o', obj], check=True)
    quoted = os.path.join(d, 'with space')
    os.makedirs(quoted, exist_ok=True)
    open(rsp, 'w').write('"-o" "%s/hi2" "-z" \'now\' "%s" "-L%s" "-lm" "-lc" "-e" "main" "-pie" "-dynamic-linker" '
                         '"/lib64/ld-linux-x86-64.so.2"\n' % (quoted, obj, '/lib/x86_64-linux-gnu'))
    q = subprocess.run([ld, '@' + rsp], capture_output=True, text=True)
    if q.returncode != 0 or not os.path.exists(os.path.join(quoted, 'hi2')):
        print('FAIL as ld: quoted response file:', q.returncode, q.stdout[-300:])
        return 1
    print('as ld: clang links through ld.weld, quietly, with a dependency file, and the program runs; '
          'quoted response files read')
    return 0


def check_shlib_undefined(exe, work):
    """What a shared library uses must be defined, for an executable: by an
    object, visibly, or a library; not if weak, nor with --allow-shlib-undefined."""
    clang = shutil.which('clang-22') or shutil.which('clang')
    if not clang:
        print('shlib undefined: not checked: no clang')
        return 0
    d = os.path.join(work, 'shlib_undefined')
    os.makedirs(d, exist_ok=True)
    ld = os.path.join(d, 'ld.weld')
    if not os.path.exists(ld):
        os.symlink(exe, ld)
    open(os.path.join(d, 'lib.c'), 'w').write(
        'extern int missing_fn(void); extern int from_exe(void); extern int hidden_in_exe(void);\n'
        '__attribute__((weak)) extern int weak_missing(void);\n'
        'int lib_a(void) { return missing_fn() + (weak_missing ? 1 : 0); }\n'
        'int lib_b(void) { return from_exe(); }\n'
        'int lib_c(void) { return hidden_in_exe(); }\n')
    open(os.path.join(d, 'main.c'), 'w').write(
        'int from_exe(void) { return 1; }\n'
        '__attribute__((visibility("hidden"))) int hidden_in_exe(void) { return 2; }\n'
        'int lib_b(void);\nint main(void) { return lib_b() - 1; }\n')
    lib = os.path.join(d, 'libt.so')
    subprocess.run([clang, '-fPIC', '-shared', '-o', lib, os.path.join(d, 'lib.c')], check=True)
    def link(*flags):
        return subprocess.run([clang, '-fuse-ld=' + ld, *flags, os.path.join(d, 'main.c'), '-L' + d, '-lt',
                               '-o', os.path.join(d, 't')], capture_output=True, text=True)
    checked, allowed = link(), link('-Wl,--allow-shlib-undefined')
    errors = sorted(l.split('`')[1].rstrip("'") for l in checked.stdout.splitlines() if 'undefined reference' in l)
    if checked.returncode == 0 or errors != ['hidden_in_exe', 'missing_fn'] or allowed.returncode != 0:
        print('FAIL shlib undefined:', checked.returncode, errors, allowed.returncode, allowed.stdout[-300:])
        return 1
    print('shlib undefined: what a shared library uses and nothing defines is an error, unless allowed')
    return 0


def gcc_with(ld, d):
    """A directory in which `ld` is the given linker, for gcc -B, whose
    -fuse-ld takes only names it knows."""
    os.makedirs(d, exist_ok=True)
    if not os.path.exists(os.path.join(d, 'ld')):
        os.symlink(ld, os.path.join(d, 'ld'))
    return '-B' + d


def check_gcc_pie(exe, work):
    """A program gcc compiles as a PIE (its default) against a shared library:
    its direct references to the library's data and to libc's stdout and
    environ need copy relocations, the aliases of environ sharing the copy,
    and its TLS the library's through the GOT. It must print what GNU ld's
    link of it prints."""
    src = os.path.join(HERE, 'data', 'gccpie')
    d = os.path.join(work, 'gccpie')
    os.makedirs(d, exist_ok=True)
    subprocess.run(['gcc', '-O2', '-shared', '-fPIC', os.path.join(src, 'lib.c'), '-o', os.path.join(d, 'libgccpie.so')],
                   check=True)
    def link_and_run(name, *flags):
        out = os.path.join(d, name)
        r = subprocess.run(['gcc', '-O2', *flags, os.path.join(src, 'main.c'), '-L' + d, '-lgccpie',
                            '-Wl,-rpath,' + d, '-o', out], capture_output=True, text=True)
        if r.returncode != 0:
            return None, r.stdout + r.stderr
        run = subprocess.run([out], capture_output=True, text=True)
        return run.stdout if run.returncode == 0 else None, run.stderr
    gnu, _ = link_and_run('main.gnu')
    ours, err = link_and_run('main', gcc_with(exe, os.path.join(d, 'ld')))
    if ours is None or ours != gnu or ours != '100 3 7 2 100 environ\n':
        print('FAIL gcc PIE: copy relocations and imported TLS:', repr(ours), repr(gnu), err[-300:])
        return 1
    print('gcc PIE: data copied (R_X86_64_COPY), aliases shared, a library\'s TLS from the executable: runs as GNU ld\'s')
    return 0


def check_self_hosting(exe, work):
    """weld links weld: goose builds it with gcc, which runs weld as its
    linker (gcc's code needs copy relocations); that weld then links the
    gcc PIE of check_gcc_pie, which must run."""
    d = os.path.join(work, 'self')
    os.makedirs(d, exist_ok=True)
    cc = os.path.join(d, 'gcc')
    with open(cc, 'w') as f:
        f.write('#!/bin/sh\nexec gcc %s "$@"\n' % gcc_with(exe, os.path.join(d, 'ld')))
    os.chmod(cc, 0o755)
    stage1 = os.path.join(d, 'weld1')
    r = subprocess.run([GOOSE, 'build', '--cc', cc, os.path.join(ROOT, 'src', 'weld.goose'), '-o', stage1],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print('FAIL self-hosting: weld did not link weld:', (r.stdout + r.stderr)[-500:])
        return 1
    src = os.path.join(HERE, 'data', 'gccpie')
    out = os.path.join(d, 'main')
    r = subprocess.run(['gcc', '-O2', gcc_with(stage1, os.path.join(d, 'ld1')), os.path.join(src, 'main.c'),
                        '-L' + os.path.join(work, 'gccpie'), '-lgccpie', '-Wl,-rpath,' + os.path.join(work, 'gccpie'),
                        '-o', out], capture_output=True, text=True)
    run = subprocess.run([out], capture_output=True, text=True) if r.returncode == 0 else None
    if run is None or run.stdout != '100 3 7 2 100 environ\n':
        print('FAIL self-hosting: the weld weld linked does not link:', r.stdout[-300:], r.stderr[-300:],
              run and run.stderr[-300:])
        return 1
    print('self-hosting: weld links weld through gcc, and that weld links a gcc PIE that runs')
    return 0


def check_build_id(exe, work):
    """XXH3 against libxxhash's, every length to 1,100 and some larger; and
    build IDs: the same for the same input, different for a byte changed."""
    failed = 0
    lib = ctypes.util.find_library('xxhash')
    if lib:
        xx = ctypes.CDLL(lib)
        xx.XXH3_64bits.restype = ctypes.c_uint64
        xx.XXH3_64bits.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
        data = random.Random(1).randbytes(1 << 21)
        path = os.path.join(work, 'xxh3.bin')
        open(path, 'wb').write(data)
        lens = list(range(1101)) + [2047, 2048, 2049, 65537, (1 << 20) + 13, 1 << 21]
        got = [int(x) for x in subprocess.run([exe, 'hash', path] + [str(n) for n in lens],
                                              capture_output=True, text=True).stdout.split()]
        wrong = [n for n, g in zip(lens, got) if g != xx.XXH3_64bits(data[:n], n)]
        if len(got) != len(lens) or wrong:
            failed += 1
            print('FAIL xxh3: differs from libxxhash at lengths', wrong[:10])
    ids = []
    for name, value in [('one', 41), ('two', 42), ('again', 41)]:      # the same names: they are in the output
        d = os.path.join(work, 'id_' + name)
        os.makedirs(d, exist_ok=True)
        open(os.path.join(d, 'f.c'), 'w').write(f'int f(void) {{ return {value}; }}\n')
        subprocess.run(['gcc', '-fPIC', '-c', 'f.c', '-o', 'f.o'], cwd=d, check=True)
        out = os.path.join(d, 'f.so')
        r = subprocess.run([exe, 'link', '-shared', '--build-id', '-o', 'f.so', 'f.o'], cwd=d, capture_output=True, text=True)
        notes = subprocess.run(['readelf', '-n', out], capture_output=True, text=True).stdout
        ids.append(next((l.split()[-1] for l in notes.splitlines() if 'Build ID' in l), None) if r.returncode == 0 else None)
    if None in ids or ids[0] != ids[2] or ids[0] == ids[1]:
        failed += 1
        print('FAIL build ID: same input, then a byte changed:', ids)
    print(f'build ID: XXH3 as libxxhash\'s{"" if lib else " (not checked: no libxxhash)"}; '
          'the same for the same output, another for a byte changed')
    return failed


def fuzz(exe, seeds, n, work):
    random.seed(1)
    archive = os.path.join(work, 'seed.a')
    subprocess.run(['ar', 'rc', archive] + seeds[:5], check=True)
    seeds = seeds + [archive]
    crashes = rejected = 0
    for k in range(n):
        src = random.choice(seeds)
        d = bytearray(open(src, 'rb').read())
        if random.random() < 0.2:
            d = d[:random.randrange(len(d))]
        else:   # half the edits land in the first 4 KB, where the headers are
            for _ in range(random.randint(1, 8)):
                i = random.randrange(min(len(d), 4096)) if random.random() < 0.5 else random.randrange(len(d))
                d[i] = random.randrange(256)
        path = os.path.join(work, 'input' + os.path.splitext(src)[1])
        open(path, 'wb').write(d)
        for cmd in ('dump', 'scan'):
            r = subprocess.run([exe, cmd, path], capture_output=True)
            text = (r.stdout[-2000:] + r.stderr).decode('latin1')
            if r.returncode not in (0, 1) or 'runtime error' in text:
                crashes += 1
                kept = os.path.join(work, f'crash{k}' + os.path.splitext(src)[1])
                os.replace(path, kept)
                print(f'FAIL {cmd} aborted on {kept}: {text[-200:]}')
                break
            if cmd == 'dump' and r.returncode == 1:
                rejected += 1
    print(f'fuzz: {n} inputs, {rejected} rejected, {crashes} aborted')
    return crashes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--fuzz', type=int, default=1000)
    ap.add_argument('files', nargs='*')
    a = ap.parse_args()
    # Goose's own objects make a good corpus of C++ when goose runs from a
    # build of it (a CMake tree beside its real path); an installed one
    # has none beside it.
    goose_dir = os.path.dirname(os.path.realpath(GOOSE))
    objects = sorted(glob.glob(os.path.join(goose_dir, '**', '*.o'), recursive=True)) \
        if os.path.exists(os.path.join(goose_dir, 'CMakeCache.txt')) else []
    gcc = shutil.which('gcc')
    cxx_lib = subprocess.run([gcc, '-print-file-name=libstdc++.a'], capture_output=True, text=True).stdout.strip() if gcc else ''
    system = [f for f in ['/usr/lib/x86_64-linux-gnu/libc.a', cxx_lib] if f and os.path.isabs(f) and os.path.exists(f)]
    files = a.files or objects + system
    work = tempfile.mkdtemp(prefix='ld_test_')
    exe = build(work)
    failed = compare_readelf(exe, files)
    failed += check_resolve(exe, work)
    failed += check_freestanding(exe, work)
    failed += check_static(exe, work)
    failed += check_comdat(exe, work)
    failed += check_shared(exe, work)
    failed += check_as_ld(exe, work)
    failed += check_shlib_undefined(exe, work)
    failed += check_gcc_pie(exe, work)
    failed += check_self_hosting(exe, work)
    failed += check_build_id(exe, work)
    seeds = [f for f in ['/usr/lib/x86_64-linux-gnu/crt1.o', '/usr/lib/x86_64-linux-gnu/crti.o',
                         '/usr/lib/x86_64-linux-gnu/crtn.o'] if os.path.exists(f)] + objects[:8]
    failed += fuzz(exe, seeds, a.fuzz, work)
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()
