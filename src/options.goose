// The command line, as ld takes it: inputs and -l libraries found in the
// -L directories, linker scripts that name more, @response files, and the
// options that set link::Options; and the --dependency-file written for
// them.
import std;
import os;
import dictionary;
import .elf;
import .link;

// The inputs on a command line like the one gcc gives ld: files, and -l
// libraries looked up in the -L directories, lib<name>.so before
// lib<name>.a unless linking statically (-static, -Bstatic; -Bdynamic
// turns that off again). Options that do not name inputs are ignored where
// they change nothing here. store holds the found paths.
fn inputs(argv: const u8[:][:], store: u8[>..]&, paths: const u8[:][>..]&, needed: link::Input[>..]&, opts: link::Options&,
          scripts: u8[>..]&) -> bool {
    open_ahead(argv);
    var dirs: const u8[:][>..] = [];
    var dynamic = true;
    var as_needed = false;               // --as-needed: a shared library only if something uses it
    var states: bool[>..] = [];          // --push-state's
    var shlib_undefined = 0;             // 1 --allow-shlib-undefined, 2 --no-; else ld's default
    var i = 0;
    while i < argv.len {
        let a = argv[i];
        i++;
        if a == "-L" || a == "-l" || a == "-o" || a == "-m" || a == "-z" || a == "--dynamic-linker" || a == "-dynamic-linker" ||
           a == "-I" || a == "-plugin" ||
           a == "-plugin-opt" || a == "-soname" || a == "-h" || a == "-rpath" || a == "-rpath-link" || a == "-u" ||
           a == "--exclude-libs" || a == "-exclude-libs" {
            guard i < argv.len else { print("missing argument after ", a); return false; }
            let v = argv[i];
            i++;
            if a == "-L" { dirs.push(v); }
            if a == "-o" { opts.output = v; }
            if a == "--exclude-libs" || a == "-exclude-libs" { exclude_libs(opts, v); }
            if a == "--dynamic-linker" || a == "-dynamic-linker" || a == "-I" { opts.interp = v; }
            if a == "-z" && v == "relro" { opts.relro = true; }
            if a == "-z" && v == "norelro" { opts.relro = false; }
            if a == "-z" && v == "defs" { opts.no_undefined = true; }
            if a == "-z" && v == "now" { opts.now = true; }
            if a == "-z" && v == "lazy" { opts.now = false; }
            if a == "-soname" || a == "-h" { opts.soname = v; }
            if a == "-rpath-link" { add_dirs(opts.rpath_link, v); }
            if a == "-rpath" {
                if opts.rpath.len > 0 { opts.rpath.push(':'); }
                opts.rpath.append(v);
            }
            if a == "-u" { opts.undefs.append(v); opts.undefs.push('\n'); }
            if a == "-l" { guard find_library(dirs, v, dynamic, as_needed, store, paths, needed, scripts) else { return false; } }
        } else if a == "-e" || a == "--entry" {
            guard i < argv.len else { print("missing argument after ", a); return false; }
            opts.entry = argv[i];
            i++;
        } else if a == "-shared" || a == "-Bshareable" {
            opts.shared = true;
        } else if a == "-pie" || a == "--pie" || a == "-pic-executable" || a == "--pic-executable" {
            opts.pie = true;
        } else if a == "-no-pie" || a == "--no-pie" {
            opts.pie = false;
        } else if starts_with(a, "--rpath-link=") || starts_with(a, "-rpath-link=") {
            add_dirs(opts.rpath_link, a[find(a, "=") + 1..]);
        } else if starts_with(a, "--exclude-libs=") || starts_with(a, "-exclude-libs=") {
            exclude_libs(opts, a[find(a, "=") + 1..]);
        } else if starts_with(a, "--dependency-file=") || starts_with(a, "-dependency-file=") {
            opts.dep_file = a[find(a, "=") + 1..];
        } else if a == "-E" || a == "--export-dynamic" {
            opts.export_dynamic = true;
        } else if a == "--no-export-dynamic" {
            opts.export_dynamic = false;
        } else if a == "-static" || a == "-Bstatic" || a == "-dn" || a == "-non_shared" {
            dynamic = false;
        } else if a == "-Bdynamic" || a == "-dy" || a == "-call_shared" {
            dynamic = true;
        } else if a == "--as-needed" || a == "--no-as-needed" {
            as_needed = a == "--as-needed";
        } else if a == "--push-state" {
            states.push(as_needed); states.push(dynamic);
        } else if a == "--pop-state" {
            guard states.len >= 2 else { print("--pop-state without --push-state"); return false; }
            dynamic = states[states.len - 1]; as_needed = states[states.len - 2];
            states.pop(); states.pop();
        } else if a == "--no-allow-shlib-undefined" || a == "--allow-shlib-undefined" {
            shlib_undefined = if a == "--allow-shlib-undefined" { 1 } else { 2 };
        } else if a == "--no-undefined" {
            opts.no_undefined = true;
        } else if starts_with(a, "--threads=") {
            let n, ok = parse_int(a[10..]);
            guard ok && n >= 0 else { print("bad thread count: ", a); return false; }
            opts.threads = n;
        } else if a == "--stats" {
            opts.stats = true;
        } else if a == "--trace" {
            opts.trace = true;
        } else if a == "--eh-frame-hdr" || a == "--no-eh-frame-hdr" {
            opts.eh_frame_hdr = a == "--eh-frame-hdr";
        } else if a == "--build-id" || starts_with(a, "--build-id=") {
            guard build_id_option(a, opts) else { print("unknown build ID kind: ", a); return false; }
        } else if starts_with(a, "-L") {
            dirs.push(a[2..]);
        } else if starts_with(a, "-l") {
            guard find_library(dirs, a[2..], dynamic, as_needed, store, paths, needed, scripts) else { return false; }
        } else if a.len > 0 && a[0] != '-' {
            guard add_input(dirs, a, dynamic, as_needed, store, paths, needed, scripts) else { return false; }
        }
    }
    close_unused();
    // Whether what shared libraries use must be defined: as GNU ld, by
    // default for an executable, not for a shared library.
    opts.shlib_check = if shlib_undefined == 0 { !opts.shared } else { shlib_undefined == 2 };
    return true;
}

// --build-id[=kind]: the kinds name a length; the ID is this linker's
// own hash of the output in any case, as mold's is. uuid is random, 0x...
// given.
fn build_id_option(a: const u8[:], opts: link::Options&) -> bool {
    let kind = if a == "--build-id" { "sha1" } else { a[11..] };
    opts.build_id_uuid = false;
    opts.build_id_given = "";
    if kind == "none" { opts.build_id = 0; return true; }
    if kind == "md5" || kind == "fast" { opts.build_id = 16; return true; }
    if kind == "sha1" { opts.build_id = 20; return true; }
    if kind == "sha256" { opts.build_id = 32; return true; }
    if kind == "uuid" { opts.build_id = 16; opts.build_id_uuid = true; return true; }
    guard starts_with(kind, "0x") && kind.len > 2 && kind.len % 2 == 0 && kind.len <= 2 + 2 * 64 else { return false; }
    for k in (kind.len - 2) / 2 {
        let v, ok = parse_int(kind[2 + 2 * k..4 + 2 * k], 16);
        guard ok else { return false; }
        opts.build_id_given.push(v as! u8);
    }
    opts.build_id = opts.build_id_given.len;
    return true;
}

// An input, and whether it is a shared library only if something uses it.
fn push_path(path: const u8[:], as_needed: bool, store: u8[>..]&, paths: const u8[:][>..]&, needed: link::Input[>..]&) {
    push_open(path, as_needed, -1, 0, "", store, paths, needed);
}

// The same for an input already open, as fd, of size bytes, whose first
// bytes are head: the link takes it over rather than open and read it again.
fn push_open(path: const u8[:], as_needed: bool, fd: i32, size: i64, head: const u8[:], store: u8[>..]&,
             paths: const u8[:][>..]&, needed: link::Input[>..]&) {
    let at = store.len;
    store.append(path);
    paths.push(store[at..]);
    var input = link::Input { as_needed: as_needed, fd: fd, size: size, head: "" };
    input.head.append(head);
    needed.push(input);
}

fn is_separator(c: u8) -> bool { c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '(' || c == ')' || c == ',' }

// The inputs opened ahead, all at once (io.c, ld_open_all): every argument
// that does not start with a -, which takes in each file the command line
// names, and some values of options as well, which are closed unused. By
// name (ahead_names: a name's hash, its number), the names themselves
// (ahead_text, each ended with a 0, from ahead_at), the sidecar's records
// (RECORD bytes each: fd, head length, size, head), and which an input took.
// Only main's reading of the command line uses them.
let RECORD = 16 + link::HEAD;
var ahead_names = dictionary<u64, i64> {};
var ahead_text: u8[>..] = [];
var ahead_at: i64[>..] = [];
var ahead_records: u8[>..] = [];
var ahead_taken: bool[>..] = [];

fn open_ahead(argv: const u8[:][:]) {
    for a in argv {
        if a.len == 0 || a[0] == '-' || contains(ahead_names, hash(a)) { continue; }
        insert(ahead_names, hash(a), ahead_at.len);
        ahead_at.push(ahead_text.len);
        ahead_text.append(a);
        ahead_text.push(0);
    }
    if ahead_at.len < 64 { return; }     // a small link: opening them one by one costs no more
    ld_open_all(ahead_text, ahead_at.len, link::HEAD, ahead_records);
    ahead_taken.resize(ahead_at.len, false);
}

// The input at path, opened ahead and not taken yet: its fd, size and
// head, which it takes; fd -1 if there is none.
fn take_ahead(path: const u8[:], head: u8[>..]&) -> i32, i64 {
    if ahead_taken.len == 0 { return -1, 0; }
    let k = get(ahead_names, hash(path));
    guard k else { return -1, 0; }
    let i = k;
    let at = ahead_at[i];
    guard ahead_text[at..at + path.len] == path && !ahead_taken[i] else { return -1, 0; }
    let r = ahead_records[i * RECORD..(i + 1) * RECORD];
    let fd = elf::u32le(r, 0) as! i32;
    if fd < 0 { return -1, 0; }
    ahead_taken[i] = true;
    head.append(r[16..16 + elf::u32le(r, 4) as! i64]);
    return fd, elf::u64le(r, 8) as! i64;
}

// Closes what was opened ahead and no input took: values of options.
fn close_unused() {
    for taken, i in ahead_taken {
        let fd = elf::u32le(ahead_records[i * RECORD..(i + 1) * RECORD], 0) as! i32;
        if !taken && fd >= 0 { ld_close(fd); }
    }
}

// An object, archive or shared library, or the inputs a linker script
// names in GROUP or INPUT, as glibc's libc.so is:
//   GROUP ( /lib/x86_64-linux-gnu/libc.so.6 libc_nonshared.a AS_NEEDED ( ld-linux-x86-64.so.2 ) )
// A name that is not absolute is looked for beside the script, then in the
// -L directories. A library a script names is taken as it is, not as
// another script. A script's name is added to scripts, a line each.
fn add_input(dirs: const u8[:][:], path: const u8[:], dynamic: bool, as_needed: bool, store: u8[>..]&,
             paths: const u8[:][>..]&, needed: link::Input[>..]&, scripts: u8[>..]&) -> bool {
    var text: u8[>..] = [];
    var fd, size = take_ahead(path, text);
    if fd < 0 {
        fd = ld_open(path);
        guard fd >= 0 else { print("cannot read ", path); return false; }
        size = ld_file_size(fd);
        // Enough to tell what it is, and for an archive its first member's header.
        let head_ok = ld_pread(fd, 0, min(size, link::HEAD), text);
        guard head_ok else { ld_close(fd); print("cannot read ", path); return false; }
    }
    if starts_with(text, "\x7fELF") || ar::is_archive(text) {
        push_open(path, as_needed, fd, size, text, store, paths, needed);
        return true;
    }
    ld_close(fd);
    text.clear();                        // a script: read it all
    guard read_file(path, text) else { print("cannot read ", path); return false; }
    scripts.append(path);
    scripts.push('\n');
    let slash = last_slash(path);
    var listing = false;
    var depth = 0;                       // parentheses open, and where AS_NEEDED's opened
    var needed_from = -1;
    var i = 0;
    while i < text.len {
        if text[i] == '/' && i + 1 < text.len && text[i + 1] == '*' {
            let end = find(text[i + 2..], "*/");
            if end < 0 { break; }
            i += end + 4;
            continue;
        }
        if text[i] == '(' { depth++; }
        if text[i] == ')' { depth--; if depth < needed_from { needed_from = -1; } }
        if is_separator(text[i]) { i++; continue; }
        let start = i;
        while i < text.len && !is_separator(text[i]) { i++; }
        let w = text[start..i];
        if w == "GROUP" || w == "INPUT" { listing = true; }
        else if w == "AS_NEEDED" { needed_from = depth + 1; }
        else if !listing || w == "OUTPUT_FORMAT" || w == "SEARCH_DIR" { listing = false; }
        else if starts_with(w, "-l") {
            let lib = library_path(dirs, w[2..], dynamic);
            guard lib.len > 0 else { print("cannot find ", w, " (named in ", path, ")"); return false; }
            push_path(lib, as_needed || needed_from >= 0, store, paths, needed);
        } else if w[0] == '/' || file_exists(w) {
            push_path(w, as_needed || needed_from >= 0, store, paths, needed);
        } else {
            var found = false;
            let beside = str(path[..slash + 1], w);
            if slash >= 0 && file_exists(beside) { push_path(beside, as_needed || needed_from >= 0, store, paths, needed); found = true; }
            for d in dirs {
                if found { break; }
                let p = str(d, "/", w);
                if file_exists(p) { push_path(p, as_needed || needed_from >= 0, store, paths, needed); found = true; }
            }
            guard found else { print("cannot find ", w, " (named in ", path, ")"); return false; }
        }
    }
    return true;
}

fn last_slash(path: const u8[:]) -> i64 {
    var k = path.len - 1;
    while k >= 0 && path[k] != '/' { k--; }
    return k;
}

// The library -l<name> names in the first of dirs that has one: lib<name>.so,
// when linking dynamically, or lib<name>.a; for -l:file, file. Empty if
// none does.
fn library_path(dirs: const u8[:][:], name: const u8[:], dynamic: bool) -> u8[>..] {
    for d in dirs {
        if name.len > 0 && name[0] == ':' {
            let path = str(d, "/", name[1..]);
            if file_exists(path) { return path; }
            continue;
        }
        if dynamic {
            let so = str(d, "/lib", name, ".so");
            if file_exists(so) { return so; }
        }
        let path = str(d, "/lib", name, ".a");
        if file_exists(path) { return path; }
    }
    return [];
}

fn find_library(dirs: const u8[:][:], name: const u8[:], dynamic: bool, as_needed: bool, store: u8[>..]&,
                paths: const u8[:][>..]&, needed: link::Input[>..]&, scripts: u8[>..]&) -> bool {
    let path = library_path(dirs, name, dynamic);
    guard path.len > 0 else { print("cannot find -l", name); return false; }
    return add_input(dirs, path, dynamic, as_needed, store, paths, needed, scripts);
}

// Adds dirs, separated by colons, to the list.
fn add_dirs(list: u8[..4096]&, dirs: const u8[:]) {
    var all: u8[>..] = [];
    all.append(list);
    if all.len > 0 { all.push(':'); }
    all.append(dirs);
    list = all;
}

// --exclude-libs: archives, by name, separated by commas or colons, or ALL,
// whose members' symbols are not exported; kept in opts a line each.
fn exclude_libs(opts: link::Options&, list: const u8[:]) {
    var names: u8[>..] = [];
    names.append(opts.exclude_libs);
    for c in list { names.push(if c == ',' || c == ':' { '\n' } else { c }); }
    names.push('\n');
    opts.exclude_libs = names;
}

// Splits a response file's text into arguments in place, as GNU ld reads
// one (libiberty's buildargv): separated by white space outside quotes,
// single or double, which are taken away, as is a backslash before any
// character, which it keeps, in quotes or not (clang quotes each argument
// of the response file it writes for a long command line). Each
// argument's start and end go to bounds, in pairs; an argument shrinks
// only, so it is written over the text read.
fn response_words(t: u8[:], bounds: i64[>..]&) {
    var r = 0;
    var w = 0;
    while r < t.len {
        while r < t.len && (t[r] == ' ' || t[r] == '\t' || t[r] == '\n' || t[r] == '\r') { r++; }
        if r == t.len { break; }
        bounds.push(w);
        var quote: u8 = 0;
        while r < t.len {
            let c = t[r];
            if c == '\\' && r + 1 < t.len { t[w] = t[r + 1]; w++; r += 2; continue; }
            if quote != 0 {
                if c == quote { quote = 0; } else { t[w] = c; w++; }
            } else if c == '\'' || c == '"' {
                quote = c;
            } else if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
                break;
            } else {
                t[w] = c; w++;
            }
            r++;
        }
        bounds.push(w);
    }
}

// The --dependency-file: a make rule of the output on every file the link
// read, each also a rule of its own, which nothing depends on, so that one
// deleted does not stop a build (as lld writes it).
fn write_dependencies(file: const u8[:], output: const u8[:], paths: const u8[:][:], scripts: const u8[:]) -> bool {
    var out: u8[>..] = [];
    var read: const u8[:][>..] = [];
    for p in paths { if !contains(read, p) { read.push(p); } }
    each_split(scripts, '\n') { if it.len > 0 && !contains(read, it) { read.push(it); } };
    escape(out, output);
    out.append(":");
    for p in read { out.append(" \\\n  "); escape(out, p); }
    out.append("\n");
    for p in read { out.append("\n"); escape(out, p); out.append(":\n"); }
    guard write_file(file, out) else { print("cannot write ", file); return false; }
    return true;
}

// A file name as make reads it: spaces and # escaped, $ doubled.
fn escape(out: u8[>..]&, name: const u8[:]) {
    for c in name {
        if c == ' ' || c == '#' { out.push('\\'); }
        if c == '$' { out.push('$'); }
        out.push(c);
    }
}
