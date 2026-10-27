// weld, a linker for x86-64 ELF, written in Goose.
//
//   weld dump file...   the symbol tables, in the format of readelf -sW
//   weld scan file...   parse every object and archive member on all cores
//   weld resolve [--trace] [-L dir] [-l name] file...
//                       resolve symbols, taking archive members as needed
//   weld link [-o out] [-e entry] [-L dir] [-l name] file...
//                       link an executable or (-shared) a shared library
//   weld hash file n... the XXH3 of the file's first n bytes, for each n
//
// Started as ld or ld.* it is a linker as compilers run one (main). The
// command line is read in options.goose; dump, scan and hash are in
// tools.goose; linking itself is link::run (link.goose).
import std;
import os;
import .link;
import .options;
import .tools;

extern fn ld_open(path: const u8[:]) -> i32;
extern fn ld_file_size(fd: i32) -> i64;
extern fn ld_pread(fd: i32, offset: i64, size: i64, out: u8[>..]&) -> bool;
extern fn ld_fork();
extern fn ld_malloc_setup();
extern fn ld_close(fd: i32);
extern fn ld_open_all(names: const u8[:], n: i64, head: i64, out: u8[>..]&);

// Whether weld was started as a linker, under a name like ld or ld.weld,
// as a compiler driver starts one (clang -fuse-ld=/path/to/ld.weld): then
// all its arguments are a link's.
fn invoked_as_ld(argv0: const u8[:]) -> bool {
    var k = argv0.len;
    while k > 0 && argv0[k - 1] != '/' { k--; }
    let name = argv0[k..];
    return name == "ld" || starts_with(name, "ld.");
}

fn main() {
    ld_malloc_setup();                   // before any thread starts
    let a = args();
    let as_ld = a.len >= 1 && invoked_as_ld(a[0]);
    if as_ld && a.len == 2 && (a[1] == "--version" || a[1] == "-v" || a[1] == "-V") {
        print("weld 0.1 (compatible with GNU ld)");
        return;
    }
    guard as_ld || (a.len >= 3 && (a[1] == "dump" || a[1] == "scan" || a[1] == "resolve" || a[1] == "link" || a[1] == "hash")) else {
        print("usage: weld dump file...\n       weld scan file...\n       weld resolve [--trace] [-L dir] [-l name] file...\n",
              "       weld link [-o out] [-e entry] [-L dir] [-l name] file...");
        exit(2);
    }
    var ok = true;
    if as_ld {
        ok = link_with(a[1..], false, true);
    } else if a[1] == "dump" {
        for p in a[2..] { if !dump(p) { ok = false; } }
    } else if a[1] == "scan" {
        ok = scan(a[2..]);
    } else if a[1] == "hash" {
        ok = hash_prefixes(a[2], a[3..]);
    } else {
        ok = link_with(a[2..], a[1] == "resolve", false);
    }
    if !ok { exit(1); }
}

// Links, or only resolves, with ld's arguments argv; quiet, saying nothing
// of a link that succeeds unless --stats, as ld.
fn link_with(argv: u8[:][:], resolve_only: bool, quiet: bool) -> bool {
    var opts = link::Options { output: "a.out", entry: "_start", trace: false, resolve_only: resolve_only,
                               build_id: 0, build_id_uuid: false, build_id_given: "", eh_frame_hdr: false, relro: true,
                               threads: 0, stats: false, shared: false, soname: "", rpath: "", undefs: "",
                               no_undefined: false, now: false, pie: false, interp: "", export_dynamic: false,
                               dep_file: "", quiet: quiet, exclude_libs: "",
                               rpath_link: "", shlib_check: false };
    var store: u8[>..] = [];
    var paths: const u8[:][>..] = [];
    var needed: link::Input[>..] = [];
    // @file: arguments read from file, as build systems and compiler
    // drivers pass command lines too long for one (response_words).
    var text: u8[>..] = [];
    var bounds: i64[>..] = [];
    var expanded: const u8[:][>..] = [];
    for arg in argv {
        if arg.len > 1 && arg[0] == '@' {
            let at = text.len;
            guard read_file(arg[1..], text) else { print("cannot read ", arg[1..]); exit(1); }
            bounds.clear();
            response_words(text[at..], bounds);
            var k = 0;
            while k < bounds.len { expanded.push(text[at + bounds[k]..at + bounds[k + 1]]); k += 2; }
        } else {
            expanded.push(arg);
        }
    }
    // Linking forks unless told not to (io.c's ld_fork); nothing has
    // started a thread yet.
    var fork = !opts.resolve_only;
    for arg in expanded {
        if arg == "--no-fork" { fork = false; }
        if arg == "--fork" { fork = !opts.resolve_only; }
    }
    if fork { ld_fork(); }
    var scripts: u8[>..] = [];
    guard inputs(expanded, store, paths, needed, opts, scripts) else { return false; }
    if opts.dep_file.len > 0 { guard write_dependencies(opts.dep_file, opts.output, paths, scripts) else { return false; } }
    return link::run(paths, needed, opts);
}
