// Linking, start to finish, as main sees it: run() and the tables it
// builds. Main opens the inputs and runs the phases; workers do the reading
// and relocating (worker.goose, protocol.goose), shards the symbol table
// (resolve.goose). Everything crosses as flat messages; docs/design.md has
// the phases as --stats names them, and every message:
//
// 1. Resolution. Parse workers read each object and archive symbol index,
//    send its global symbols to the shards, and send main the object's
//    sections. Archive members are taken in rounds (resolve.goose).
// 2. Export. Main numbers the symbols shard by shard; each shard sends
//    what defines each of its symbols, and the global id of every
//    occurrence of one in an object.
// 3. Layout, in main: output sections, segments and every symbol's
//    address, then each object's import vector, its global symbols'
//    addresses, gathered by id.
// 4. Relocation. Each worker takes an object, its sections' places and its
//    import vector, relocates the sections and writes them into the output
//    file at their offsets.
namespace link;
import std;
import os;
import dictionary;
import .elf;
import .archive;
import .resolve;
import .layout;
import .reloc;
import .ehframe;
import .dso;
import .dynamic;
import .xxh3;
import .merge;
import .protocol;
import .worker;

extern fn ld_open(path: const u8[:]) -> i32;
extern fn ld_create(path: const u8[:], size: i64) -> i32;
extern fn ld_file_size(fd: i32) -> i64;
extern fn ld_pread(fd: i32, offset: i64, size: i64, out: u8[>..]&) -> bool;
extern fn ld_pwrite(fd: i32, offset: i64, data: const u8[:]) -> bool;
extern fn ld_close(fd: i32);
extern fn ld_reserve_fds(n: i32);
extern fn ld_create_early(path: const u8[:], bound: i64) -> i32;
extern fn ld_populate(offset: i64, size: i64);
extern fn ld_discard();
extern fn ld_prefer_huge(buf: u8[>..]&, n: i64);
extern fn ld_remove_old(path: const u8[:]);
extern fn ld_finish();
extern fn ld_notify();

// Whether the archive at path is one --exclude-libs names (list, a line
// each, ALL for any): by its file's name.
fn excluded(list: const u8[:], path: const u8[:]) -> bool {
    if list.len == 0 { return false; }
    var k = path.len;
    while k > 0 && path[k - 1] != '/' { k--; }
    let name = path[k..];
    var found = false;
    each_split(list, '\n') { if it == "ALL" || it == name { found = true; } };
    return found;
}

// Writes data to the output at offset, adding it to the build ID's sum.
fn put(out: i32, offset: i64, data: const u8[:], sum: xxh3::IdSum&) -> bool {
    xxh3::add(sum, offset, data);
    return ld_pwrite(out, offset, data);
}

// Symbols the linker defines unless an input does; then the entry symbol,
// which the linker's own pseudo-object references.
let LINKER_DEFINED = ["_GLOBAL_OFFSET_TABLE_", "_DYNAMIC", "__ehdr_start", "__executable_start",
    "_etext", "etext", "__etext", "_edata", "edata", "_end", "end", "__bss_start",
    "__init_array_start", "__init_array_end", "__fini_array_start", "__fini_array_end",
    "__preinit_array_start", "__preinit_array_end", "__rela_iplt_start", "__rela_iplt_end",
    "_TLS_MODULE_BASE_", "__dso_handle",
    "__tls_get_addr"];      // its calls relax away in an executable; ld.so's later

// The value of LINKER_DEFINED[i] in the laid-out image.
fn linker_value(i: i64, outs: const layout::Out[layout::NCLASSES]&, img: const layout::Image&, synth: const Synthetic&) -> u64 {
    let n = LINKER_DEFINED[i];
    if n == "_GLOBAL_OFFSET_TABLE_" { return synth.got; }
    if n == "__rela_iplt_start" { return synth.irel; }
    if n == "__rela_iplt_end" { return synth.irel + 24 * synth.nstubs as! u64; }
    if n == "__ehdr_start" || n == "__executable_start" { return layout::BASE; }
    if n == "_etext" || n == "etext" || n == "__etext" { return img.load[1].addr + img.load[1].memsz; }
    if n == "_edata" || n == "edata" { return img.load[2].addr + img.load[2].filesz; }
    if n == "_end" || n == "end" { return img.load[2].addr + img.load[2].memsz; }
    if n == "__bss_start" { return outs[layout::BSS].addr; }
    if n == "__init_array_start" { return outs[layout::INIT_ARRAY].addr; }
    if n == "__init_array_end" { return outs[layout::INIT_ARRAY].addr + outs[layout::INIT_ARRAY].size; }
    if n == "__fini_array_start" { return outs[layout::FINI_ARRAY].addr; }
    if n == "__fini_array_end" { return outs[layout::FINI_ARRAY].addr + outs[layout::FINI_ARRAY].size; }
    if n == "__preinit_array_start" { return outs[layout::PREINIT_ARRAY].addr; }
    if n == "__preinit_array_end" { return outs[layout::PREINIT_ARRAY].addr + outs[layout::PREINIT_ARRAY].size; }
    if n == "_TLS_MODULE_BASE_" { return img.tls.addr; }
    return 0;
}

// build_id is how many bytes the build ID has, 0 for none: from a hash of
// the output, random for uuid, or the bytes given.
// shared makes a shared library, named soname, whose undefined symbols
// are allowed unless no_undefined; undefs are -u's symbols, one a line.
// pie makes a position-independent executable, loaded by interp, which
// exports what shared libraries use of it, all it defines if
// export_dynamic. exclude_libs names archives, a line each (or ALL),
// whose members' definitions are hidden: not exported (--exclude-libs).
struct Options { output: u8[..4096], entry: u8[..256], trace: bool, resolve_only: bool, build_id: i64,
                 build_id_uuid: bool, build_id_given: u8[..64], eh_frame_hdr: bool, relro: bool, threads: i64,
                 stats: bool, shared: bool, soname: u8[..256], rpath: u8[..4096], undefs: u8[..4096],
                 no_undefined: bool, now: bool, pie: bool, interp: u8[..256], export_dynamic: bool,
                 dep_file: u8[..4096], quiet: bool, exclude_libs: u8[..4096], rpath_link: u8[..4096], shlib_check: bool }

// What main knows of an object: where it is, and where its sections and
// imports are in the arrays that hold them for all objects.
// rela_index and rela_count are its run-time relocations' place in .rela.dyn.
// pieces counts its merged strings, piece_base numbers the first of them
// among all objects'. eh_sec is its .eh_frame's index in secs, if the FDEs
// of code left out are left out of it, else -1. abs64, locals, local_strs
// and fdes are its totals (ObjInfo), less those of its groups that lose.
struct Obj { prio: u64, offset: i64, size: i64, first_global: i64, nsyms: i64, sec_base: i64, nsecs: i64, imp_base: i64,
             abs_locals: i64, abs_strs: i64, sym_index: i64, str_index: i64, rela_index: i64, rela_count: i64,
             pieces: i64, piece_base: i64, eh_sec: i64, abs64: i64, locals: i64, local_strs: i64, fdes: i64,
             merge_bytes: i64 }

let STT_GNU_IFUNC: u8 = 10;
let SHT_DYNAMIC: u32 = 6;
let SHT_DYNSYM: u32 = 11;
let SHT_GNU_HASH: u32 = 0x6ffffff6;
let SHT_GNU_VERNEED: u32 = 0x6ffffffe;
let SHT_GNU_VERSYM: u32 = 0x6fffffff;

// Whether a symbol is in a shared library's dynamic symbol table, and how.
let NOT_DYNAMIC: u8 = 0;
let EXPORTED: u8 = 1;
let IMPORTED: u8 = 2;

// The name of version index in a shared library's DsoInfo versions; empty
// if it has no such version.
fn version_name(versions: const u8[:], index: u32) -> const u8[:] {
    var at = 0;
    while at + 3 <= versions.len {
        let i: u32 = versions[at] | (versions[at + 1] as u32) << 8;
        let rest = versions[at + 2..];
        let z = find_any(rest, elf::NUL);
        if z < 0 { break; }
        if i == index { return rest[..z]; }
        at += 2 + z + 1;
    }
    return versions[..0];
}

// What a shard's part of the output's symbol table takes.
struct ShardTable { locals: i64, local_strs: i64, globals: i64, global_strs: i64 }

// A section's place in the order of the output.
struct Placement { class: u8, named: bool, key: u64, order: u64, sec: u32 }
fn before(a: Placement, b: Placement) -> bool {
    if a.class != b.class { return a.class < b.class; }
    if a.named != b.named { return !a.named; }
    if a.key != b.key { return a.key < b.key; }
    return a.order < b.order;
}
struct Range { start: u64, end: u64 }

// Where the sections the linker makes go. nstubs counts the IRELATIVE
// relocations .rela.iplt has, which a shared library has in .rela.dyn.
struct Synthetic { got: u64, igot: u64, stubs: u64, irel: u64, build_id: u64, property: u64, eh_hdr: u64,
                   nslots: i64, nstubs: i64, plt: u64, hash: u64, dynsym: u64, dynstr: u64, versym: u64, verneed: u64,
                   rela_dyn: u64, dynamic: u64 }
// A section the linker makes, at offset at in the output section of its class.
struct Extra { class: u8, name: u8[..24], kind: u32, at: u64, size: u64, align: u64, entsize: u64 }

// A shared library: where its name, versions, the names of the libraries
// it needs and its run path are in main's dso_text (DsoInfo).
struct DsoRec { prio: u64, name_at: i64, name_len: i64, ver_at: i64, ver_len: i64, needed_at: i64, needed_len: i64,
                run_at: i64, run_len: i64 }

// Opens the library a shared library needs, by the name its DT_NEEDED
// gives: as given if a path, else in the first directory it is in of
// -rpath-link's, -rpath's, the library's own run path ($ORIGIN its own
// directory, origin) and the system's, as GNU ld looks. Its path goes to
// paths; the file descriptor, or -1 if there is none that is an x86-64
// shared library.
fn find_needed(name: const u8[:], rpath_link: const u8[:], rpath: const u8[:], runpath: const u8[:],
               origin: const u8[:], paths: u8[>..]&) -> i32 {
    fn try(path: const u8[:]) -> i32 {
        let fd = ld_open(path);
        if fd < 0 { return -1; }
        var head: u8[>..] = [];
        if ld_pread(fd, 0, 20, head) && head.len == 20 && head[..4] == "\x7fELF" && head[4] == 2 &&
           elf::u16le(head, 16) == dso::ET_DYN && elf::u16le(head, 18) == 62 {
            paths.append(path);
            return fd;
        }
        ld_close(fd);
        return -1;
    }
    if contains(name, '/') { return try(name); }
    let lists = [rpath_link, rpath, runpath, "/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu:/lib64:/usr/lib64:/lib:/usr/lib"];
    var fd: i32 = -1;
    var dir: u8[>..] = [];
    for list, k in lists {
        each_split(list, ':') {
            if fd < 0 && it.len > 0 {
                dir.clear();
                if k == 2 && starts_with(it, "$ORIGIN") { dir.append(origin); dir.append(it[7..]); }
                else if k == 2 && starts_with(it, "${ORIGIN}") { dir.append(origin); dir.append(it[9..]); }
                else { dir.append(it); }
                dir.push('/');
                dir.append(name);
                fd = try(dir);
            }
        };
    }
    return fd;
}

// A round-one job, before it is queued.
struct Start { kind: u8, file: i64, offset: i64, size: i64, aux: i64 }

// as_needed says of each input whether, as a shared library, it is needed
// only if something uses it.
// An input as the command line gave it: whether it is a shared library
// --as-needed; and if already open (fd -1 if not), its file descriptor,
// size, and first HEAD bytes (fewer if it is smaller): an ELF header's
// start, or an archive's magic and first member header.
let HEAD = ar::MAGIC.len + ar::HDR_SIZE;
struct Input { as_needed: bool, fd: i32, size: i64, head: u8[..HEAD] }

// Opens each input (or takes it as options.goose opened it), into fds and
// sizes. The errors, and the total that sizes the threads: what is read,
// where a shared library's file, its debugging information above all, is
// far larger than the dynamic symbol table weld reads of it, which a 64th
// of it stands for.
fn open_inputs(paths: const u8[:][:], given: const Input[:], fds: i32[>..]&, sizes: i64[>..]&) -> i64, i64 {
    var errors = 0;
    var total = 0;
    var head: u8[>..] = [];
    for p, i in paths {
        let opened = given[i].fd >= 0;
        let fd = if opened { given[i].fd } else { ld_open(p) };
        if fd < 0 { print("cannot open ", p); errors++; }
        fds.push(fd);
        let size = if fd < 0 { 0 } else if opened { given[i].size } else { ld_file_size(fd) };
        sizes.push(size);
        head.clear();
        if opened { head.append(given[i].head); } else if fd >= 0 { ld_pread(fd, 0, min(size, HEAD), head); }
        let shared = head.len >= 18 && head[..4] == "\x7fELF" && elf::u16le(head[..18], 16) == dso::ET_DYN;
        total += if shared { clamp(size >> 6, 64 << 10, 4 << 20) } else { size };
    }
    return errors, total;
}

// How many workers and shards, for total bytes of input. 8 MB of input a
// worker, two at least: a thread takes 0.2 ms to start, and most of an
// archive's bytes are never read, but one worker alone leaves the rounds no
// overlap. At most two thirds of the hardware threads, which leaves the
// rest to the shards and main, busy alongside the workers while symbols are
// resolved: a 2,266-object link on 20 hardware threads (10 cores) took 266 ms
// with 12 workers, 283 ms with 20. Shards by the inputs' size alone:
// symbols are numbered shard by shard, so that the output must not depend
// on the machine or --threads.
fn thread_counts(total: i64, opts: const Options&) -> i64, i64 {
    let nworkers = if opts.threads > 0 { min(opts.threads, max(1, hardware_threads())) }
                   else { clamp(total >> 23, 2, max(2, 2 * hardware_threads() / 3)) };
    return nworkers, clamp(total >> 22, 1, resolve::MAX_SHARDS);
}

// The symbols of the linker's pseudo-object, prio 0: those it defines
// (LINKER_DEFINED), the entry, _init and _fini for DT_INIT and DT_FINI if
// they are there, and -u's.
fn linker_symbols(opts: const Options&, recs: resolve::Rec[>..]&) {
    for name, i in LINKER_DEFINED {
        recs.push(resolve::Rec { hash: hash(name), prio: 0, size: 0, value: 0, sym: i as! u32, shndx: 0,
                                 kind: resolve::PROVIDED, stype: 0, bind: 0, other: 0, need: 0, name: name });
    }
    // A shared library needs no entry, but has one if it is there.
    recs.push(resolve::Rec { hash: hash(opts.entry), prio: 0, size: 0, value: 0, sym: LINKER_DEFINED.len as! u32,
                             shndx: 0, kind: if opts.shared { resolve::UNDEF_WEAK } else { resolve::UNDEF }, stype: 0,
                             bind: 0, other: 0, need: 0, name: opts.entry });
    for name in ["_init", "_fini"] {
        recs.push(resolve::Rec { hash: hash(name), prio: 0, size: 0, value: 0, sym: recs.len as! u32, shndx: 0,
                                 kind: resolve::UNDEF_WEAK, stype: 0, bind: 0, other: 0, need: 0, name: name });
    }
    each_split(opts.undefs, '\n') {                 // -u: referenced, so that archives define them
        if it.len > 0 {
            recs.push(resolve::Rec { hash: hash(it), prio: 0, size: 0, value: 0, sym: recs.len as! u32, shndx: 0,
                                     kind: resolve::UNDEF, stype: 0, bind: 0, other: 0, need: 0, name: it });
        }
    };
}

// Queues round one: every object, shared library and archive symbol index,
// largest first, so that the first worker takes the input that sets how
// long the round lasts. How many jobs, and the inputs that could not be.
fn queue_round_one(paths: const u8[:][:], given: const Input[:], fds: const i32[:], sizes: const i64[:], nshards: i64,
                   opts: const Options&) -> i64, i64 {
    var errors = 0;
    var starts: Start[>..] = [];
    var hdr: u8[>..] = [];
    for p, i in paths {
        let fd = fds[i];
        if fd < 0 { continue; }
        let size = sizes[i];
        hdr.clear();
        if given[i].fd >= 0 { hdr.append(given[i].head); }
        else if !ld_pread(fd, 0, min(size, HEAD), hdr) { print("cannot read ", p); errors++; continue; }
        if !ar::is_archive(hdr) {
            let shared = hdr.len >= 18 && elf::u16le(hdr[..18], 16) == dso::ET_DYN;
            starts.push(Start { kind: if shared { JOB_SHARED } else { JOB_OBJECT }, file: i, offset: 0, size: size, aux: 0 });
            continue;
        }
        if hdr.len < ar::MAGIC.len + ar::HDR_SIZE { continue; }              // an empty archive
        let raw, isize, ok = ar::parse_header(hdr[ar::MAGIC.len..]);
        let w = if ok { ar::index_width(raw) } else { 0 };
        if w == 0 || isize > size - ar::MAGIC.len - ar::HDR_SIZE { print(p, ": no archive symbol index (run ranlib)"); errors++; continue; }
        starts.push(Start { kind: JOB_INDEX, file: i, offset: ar::MAGIC.len + ar::HDR_SIZE, size: isize, aux: w });
    }
    sort(starts) { a, b => a.size > b.size || (a.size == b.size && a.file < b.file) };
    for st in starts {
        var j = job(st.kind, fds[st.file], nshards, st.file + 1, st.offset, st.size, st.aux, paths[st.file]);
        j.refs = opts.pie || opts.shlib_check;   // a shared library's references then matter (resolve::DSO_REF)
        qput(j);
    }
    return starts.len, errors;
}

// What the shards answer once resolution is done (resolve::Final): the
// counts, the error lines, and what each shard's part of the output's
// symbol table takes.
struct Resolved { symbols: i64, undefined: i64, duplicates: i64, shlib_undefined: i64, digest: u64,
                  tables: ShardTable[resolve::MAX_SHARDS] }

// Collects the shards' Finals (counts takes each shard's number of
// symbols) and prints the errors they found, sorted, so that they do not
// depend on the threads: duplicates, undefined symbols, and with
// shlib_check what shared libraries use that nothing defines.
fn finish_resolution(nshards: i64, paths: const u8[:][:], opts: const Options&, counts: i64[>..]&) -> Resolved {
    counts.resize(nshards, 0);
    var r = Resolved { symbols: 0, undefined: 0, duplicates: 0, shlib_undefined: 0, digest: 0,
                       tables: [ShardTable { locals: 0, local_strs: 0, globals: 0, global_strs: 0 }; resolve::MAX_SHARDS] };
    var reported: u8[>..] = [];
    for k in nshards {
        let f = qget<resolve::Final>();
        counts[f.shard] = f.symbols;
        r.tables[f.shard] = ShardTable { locals: f.locals, local_strs: f.local_strs, globals: f.globals, global_strs: f.global_strs };
        r.symbols += f.symbols; r.undefined += f.undefined; r.duplicates += f.duplicates;
        r.shlib_undefined += f.shlib_undefined;
        r.digest ^= f.digest;
        reported.append(f.names);
    }
    var lines = split(reported, '\n');
    sort(lines) { a, b => compare(a, b) < 0 };
    for l in lines {
        if starts_with(l, "D ") { print("duplicate symbol: ", l[2..]); }
        if starts_with(l, "U ") { print("undefined symbol: ", l[2..]); }
        if starts_with(l, "S ") && opts.shlib_check {
            var k = l.len;
            while k > 2 && l[k - 1] != ' ' { k--; }
            let file, _ = parse_int(l[k..]);
            print(if file >= 1 && file <= paths.len { paths[file - 1] } else { "a shared library" },
                  ": undefined reference to `", l[2..k - 1], "'");
        }
    }
    return r;
}

// The most the output can take, and what it surely takes, before layout
// (see run, where the output is made early): every section as kept, padded
// as most, the linker's own as large as the symbols could make them; and
// the sections in no COMDAT group with a symbol table entry for each
// global symbol. names is the bytes of library names and paths.
fn output_bounds(secs: const Sec[:], objs: const Obj[:], tables: const ShardTable[:], nshards: i64, symbols: i64,
                 names: i64) -> u64, u64 {
    var bound: u64 = 1 << 20;
    var surely: u64 = 0;
    var align_most: u64 = 1;
    for &sec in secs {
        if sec.class == layout::DISCARD { continue; }
        bound += sec.size + sec_align(sec);
        if sec.group == 0 { surely += sec.size; }
        align_most = max(align_most, sec_align(sec));
    }
    var locals_most = 1 + symbols;
    var strs_most = 1;
    for &o in objs {
        bound += o.merge_bytes as! u64 + 24 * o.abs64 as! u64 + 8 * o.fdes as! u64;
        locals_most += o.abs_locals + o.locals;
        strs_most += o.abs_strs + o.local_strs;
    }
    for k in nshards { locals_most += tables[k].locals; strs_most += 2 * (tables[k].local_strs + tables[k].global_strs); }
    let n = symbols as! u64;
    bound += 24 * locals_most as! u64 + strs_most as! u64 + names as! u64 +
             (8 * 3 + 16 * 2 + 24 * 2 + 2 + 32 + 24 * 4) * n + (layout::NCLASSES as! u64 + 8) * (align_most + layout::PAGE);
    return bound, surely + 24 * n;
}

// An object by its prio. A prio is its input's number and, for an archive
// member, its offset, so each input's objects are a run of objs (in prio
// order), which file_first gives (the next input's run ends it): an object
// file at once, a member by a search of its archive's. Lookups come in
// runs from one object, so the last is remembered.
struct ObjIndex { last_prio: u64, last_at: i64, file_first: i64[>..] }

fn index_objects(ix: ObjIndex&, objs: const Obj[:], npaths: i64) {
    ix.file_first.resize(npaths + 2, 0);
    for o in objs { ix.file_first[resolve::prio_file(o.prio) + 1]++; }
    for f in npaths + 1 { ix.file_first[f + 1] += ix.file_first[f]; }
}

fn find_object(ix: ObjIndex&, objs: const Obj[:], p: u64) -> i64 {
    if p == ix.last_prio { return ix.last_at; }
    let f = resolve::prio_file(p);
    var lo = ix.file_first[f];
    var hi = ix.file_first[f + 1];
    while hi - lo > 1 {
        let mid = (lo + hi) / 2;
        if objs[mid].prio <= p { lo = mid; } else { hi = mid; }
    }
    assert(lo < hi && objs[lo].prio == p);
    ix.last_prio = p;
    ix.last_at = lo;
    return lo;
}

// Every copy of a COMDAT group but the kept one is left out: the shards
// name the losers (resolve::Losers). A losing group's SHT_GROUP section is
// marked, by its index among all sections; then one pass leaves out each
// section of a marked group, and takes its totals off its object's. The
// bytes left out.
fn leave_out_group_copies(nshards: i64, objs: Obj[>..]&, secs: Sec[>..]&, index: ObjIndex&) -> u64 {
    var dropped: u64 = 0;
    var losing: bool[>..] = [];
    losing.resize(secs.len, false);
    for k in nshards {
        let m = qget<resolve::Losers>();
        for x in m.groups {
            let o .= objs[find_object(index, objs, x.prio)];
            losing[o.sec_base + (x.sym & ~resolve::GROUP_MARK)] = true;
        }
    }
    for &o in objs {
        var eh_bytes: u64 = 0;           // and the FDEs of their code
        for &sec, k in secs[o.sec_base..o.sec_base + o.nsecs] {
            if losing[o.sec_base + k] {  // a losing group: its totals leave the object's
                let t = group_totals(sec);
                o.abs64 -= t.abs64 as! i64;
                o.fdes -= t.fdes as! i64;
                o.locals -= t.locals as! i64;
                o.local_strs -= t.local_strs as! i64;
                eh_bytes += t.eh_bytes;
            } else if sec.group != 0 && losing[o.sec_base + sec.group] && sec.class != layout::DISCARD {
                sec.class = layout::DISCARD;
                dropped += sec.size;
            }
        }
        if o.eh_sec >= 0 && eh_bytes > 0 {
            secs[o.eh_sec].size -= eh_bytes;
            dropped += eh_bytes;
        }
    }
    return dropped;
}

// The shards' answers about merged strings (resolve::MergeDone), one after
// another in data: shard k's from at[k] to end[k].
struct Merged { at: i64[resolve::MAX_SHARDS], end: i64[resolve::MAX_SHARDS], data: u64[>..] }

fn shard_part(m: const Merged&, k: i64) -> const u64[:] { m.data[m.at[k]..m.end[k]] }

// Lays out the merged strings: each merge group (mgroups, ascending) one
// section, pushed onto secs (merge_sec), after the rest of its output
// section's, each shard's part of it in turn at part_at[group * nshards +
// shard] (merge.goose).
fn lay_out_merge_groups(nshards: i64, secs: Sec[>..]&, merged: Merged&, mgroups: u64[>..]&, part_at: u64[>..]&,
                        merge_sec: i64[>..]&) {
    for k in nshards {
        let m = qget<resolve::MergeDone>();
        merged.at[m.shard] = merged.data.len;
        merged.data.append(m.data);
        merged.end[m.shard] = merged.data.len;
        for g in m.data[0] as! i64 { if !contains(mgroups, m.data[1 + 2 * g]) { mgroups.push(m.data[1 + 2 * g]); } }
    }
    sort(mgroups) { a, b => a < b };
    part_at.resize(mgroups.len * nshards, 0);
    for g, gi in mgroups {
        let align = merge::align_of(g as! u32);
        var size: u64 = 0;
        for k in nshards {
            let d = shard_part(merged, k);
            for j in d[0] as! i64 {
                if d[1 + 2 * j] != g { continue; }
                size = layout::align_up(size, align);
                part_at[gi * nshards + k] = size;
                size += d[2 + 2 * j];
            }
        }
        merge_sec.push(secs.len);
        secs.push(Sec { class: merge::class_of(g as! u32), named: false, align2: log2(align), group: 0,
                        key: merge::key_of(g as! u32), size: size, addr: 0 });
    }
}

// Every section that goes in the output, in the order it goes there
// (sorted), and each output section's size and alignment (outs), each
// section's address its offset in its output section for now. By class,
// keeping command-line order, which most classes need alone; a class's
// sections with a key or a name for __start_ go after the rest, sorted.
// count[c] is where class c starts in sorted.
fn place_sections(objs: const Obj[:], secs: Sec[>..]&, merge_sec: const i64[:], count: i64[layout::NCLASSES + 1]&,
                  sorted: Placement[>..]&, outs: layout::Out[layout::NCLASSES]&) {
    var order: Placement[>..] = [];
    for &o, oi in objs {
        for k in o.nsecs {
            let s .= secs[o.sec_base + k];
            if s.class != layout::DISCARD {
                order.push(Placement { class: s.class, named: s.named, key: s.key, order: (oi as! u64) << 32 | k as! u64,
                                       sec: (o.sec_base + k) as! u32 });
            }
        }
    }
    for i, gi in merge_sec {
        let s .= secs[i];
        order.push(Placement { class: s.class, named: false, key: s.key, order: 0xffffffff00000000 | gi as! u64,
                               sec: i as! u32 });
    }
    for x in order { count[x.class + 1]++; }
    for c in layout::NCLASSES { count[c + 1] += count[c]; }
    var fill = count;
    sorted.resize(order.len, Placement { class: 0, named: false, key: 0, order: 0, sec: 0 });
    for x in order { if !x.named && x.key == 0 { sorted[fill[x.class]] = x; fill[x.class]++; } }
    for x in order { if x.named || x.key != 0 { sorted[fill[x.class]] = x; fill[x.class]++; } }
    for c in layout::NCLASSES {
        var first = count[c];
        while first < count[c + 1] && !sorted[first].named && sorted[first].key == 0 { first++; }
        if count[c + 1] - first > 1 { sort(sorted[first..count[c + 1]]) { a, b => before(a, b) }; }
    }
    for x in sorted {
        let s .= secs[x.sec];
        let out .= outs[s.class];
        out.align = max(out.align, sec_align(s));
        s.addr = layout::align_up(out.size, sec_align(s));      // the offset in its output section, for now
        out.size = s.addr + s.size;
    }
}

// Links paths (given says how options.goose found them) as opts says, or
// with resolve_only only resolves. The phases, each marked "Phase N" below,
// and their --stats lines (docs/design.md):
//
// 1. Inputs and round one: open_inputs, thread_counts, linker_symbols,
//    queue_round_one; the workers and shards start.
// 2. Resolution: archive members round after round, the libraries the
//    given ones need, finish_resolution and its errors ("resolved").
// 3. The output, made early at output_bounds, its surely part faulted in by
//    two workers ("output made").
// 4. Export and layout: symbol ids and definitions, the object index,
//    leave_out_group_copies, lay_out_merge_groups, place_sections ("sections
//    placed").
// 5. The linker's own sections: exports and imports, GOT, PLT, IFUNC stubs,
//    the dynamic tables, then every address ("addresses assigned"), and each
//    object's imports gathered ("imports gathered").
// 6. Section headers and the symbol table's layout ("symbol table laid out").
// 7. Writing: the headers and the linker's sections here; relocation jobs
//    for the objects, the symbol tables on the shards; then the build ID
//    ("written").
fn run(paths: const u8[:][:], given: const Input[:], opts: const Options&) -> bool {
    // Phase 1: inputs and round one.
    let t0 = clock_ns();
    // A shared library or a PIE executable: placed by the dynamic linker,
    // with its tables (dyn_out).
    let dyn_out = opts.shared || opts.pie;
    if dyn_out { layout::BASE = 0; }    // before any worker copies it
    if opts.pie { layout::NPHDRS = 14; }
    var errors = 0;
    // The build ID's sum over main's writes, and the workers' and shards'
    // as they report them (xxh3::IdSum); not for an ID given or random.
    var idsum = xxh3::IdSum { on: opts.build_id > 0 && opts.build_id_given.len == 0 && !opts.build_id_uuid, a: 0, b: 0 };
    var fds: i32[>..] = [];
    var sizes: i64[>..] = [];
    let open_errors, total = open_inputs(paths, given, fds, sizes);
    if open_errors > 0 { return false; }      // not a flood of undefined symbols after it
    // Room for what is opened once threads run, a PIE's needed libraries
    // above all, which would cost a wait each time the table doubles; so
    // before ld_remove_old's thread.
    ld_reserve_fds((fds.len + 256) as! i32);
    if !opts.resolve_only { ld_remove_old(opts.output); }       // while the link runs
    let nworkers, nshards = thread_counts(total, opts);

    var objs: Obj[>..] = [];
    var secs: Sec[>..] = [];
    var and_features: u32 = 0xffffffff;   // what every object's code has
    var isa_needed: u32 = 0;
    var described = 0;                   // descriptions sent, to collect after the last round
    var merge_counts: i64[resolve::MAX_SHARDS] = [0; resolve::MAX_SHARDS];    // messages of strings each shard got
    var dsos_described = 0;
    var any_tlsld = false;
    // The shared libraries, in command-line order once sorted: each one's
    // name and its versions (DsoInfo) in dso_text.
    var dsos: DsoRec[>..] = [];
    var indirect: DsoRec[>..] = [];       // the libraries those need, a PIE's (follow_needed)
    var dso_text: u8[>..] = [];
    fn take(done: JobDone) {
        errors += done.errors;
        idsum.a += done.ida;
        idsum.b += done.idb;
        described += done.objects;
        dsos_described += done.dsos;
    }
    fn collect() {
        for k in dsos_described {
            let d = qget<DsoInfo>();
            let at = dso_text.len;
            dso_text.append(d.soname);
            let ver_at = dso_text.len;
            dso_text.append(d.text);
            let rec = DsoRec { prio: d.prio, name_at: at, name_len: d.soname.len, ver_at: ver_at, ver_len: d.ver_len,
                               needed_at: ver_at + d.ver_len, needed_len: d.needed_len,
                               run_at: ver_at + d.ver_len + d.needed_len, run_len: d.text.len - d.ver_len - d.needed_len };
            if d.indirect { indirect.push(rec); } else { dsos.push(rec); }
        }
        dsos_described = 0;
        for k in described {
            let info = qget<ObjInfo>();
            objs.push(Obj { prio: info.prio, offset: info.offset, size: info.size, first_global: info.first_global,
                            nsyms: info.nsyms, sec_base: secs.len, nsecs: info.secs.len, imp_base: 0,
                            abs_locals: info.abs_locals, abs_strs: info.abs_strs, sym_index: 0, str_index: 0,
                            rela_index: 0, rela_count: 0, pieces: info.pieces, piece_base: 0,
                            eh_sec: if info.eh > 0 { secs.len + info.eh } else { -1 }, abs64: info.abs64,
                            locals: info.locals, local_strs: info.local_strs, fdes: info.fdes,
                            merge_bytes: info.merge_bytes });
            secs.append(info.secs);
            for k in resolve::MAX_SHARDS { if info.merge_mask & (1 as u32) << k != 0 { merge_counts[k]++; } }
            and_features &= info.features;
            isa_needed |= info.isa;
            any_tlsld = any_tlsld || info.tlsld;
        }
        described = 0;
    }
    fn wait(n: i64) { for i in n { take(qget<JobDone>()); } }

    // The linker's pseudo-object, prio 0: what it defines, and the entry.
    var recs: resolve::Rec[>..] = [];
    linker_symbols(opts, recs);
    let pseudo_syms = recs.len;
    resolve::send(recs, nshards);
    objs.push(Obj { prio: 0, offset: 0, size: 0, first_global: 0, nsyms: pseudo_syms, sec_base: 0,
                    nsecs: 0, imp_base: 0, abs_locals: 0, abs_strs: 0, sym_index: 0, str_index: 0, rela_index: 0,
                    rela_count: 0, pieces: 0, piece_base: 0, eh_sec: -1, abs64: 0, locals: 0, local_strs: 0, fdes: 0,
                    merge_bytes: 0 });

    // Round one, queued before any thread starts. Workers start before
    // shards: they read for a while before they send anything.
    let jobs, start_errors = queue_round_one(paths, given, fds, sizes, nshards, opts);
    errors += start_errors;
    for i in nworkers { thread_spawn(worker); }
    for k in nshards { thread_spawn(resolve::shard_worker, k); }
    fn stat(what: const u8[:]) { if opts.stats { print("  ", (clock_ns() - t0) / 1000, " us: ", what); } }
    stat(str(nworkers, " workers, ", nshards, " shards started; ", jobs, " jobs queued"));
    wait(jobs);
    stat("round 1 read");

    // Phase 2: resolution. The archive members that define what is still
    // undefined, round after round, until a round takes none.
    var taken = dictionary<u64, bool> {};
    var members: u64[>..] = [];
    var rounds = 1;
    var fresh: u64[>..] = [];
    loop {
        resolve::broadcast(resolve::CMD_FLUSH, nshards);
        fresh.clear();
        for k in nshards {
            let f = qget<resolve::Flushed>();
            for x in f.extract { if insert(taken, x, true) { fresh.push(x); } }
        }
        stat(str("flushed: ", fresh.len, " members to take"));
        if fresh.len == 0 { break; }
        rounds++;
        members.append(fresh);
        // About two jobs a worker, each the members of one archive.
        sort(fresh) { a, b => a < b };
        let per = max(1, (fresh.len + 2 * nworkers - 1) / (2 * nworkers));
        var jobs = 0;
        var i = 0;
        while i < fresh.len {
            let file = resolve::prio_file(fresh[i]);
            var j = job(JOB_MEMBER, fds[file - 1], nshards, file, 0, 0, 0, paths[file - 1]);
            j.hide = excluded(opts.exclude_libs, paths[file - 1]);
            while i < fresh.len && resolve::prio_file(fresh[i]) == file && j.data.len < per {
                j.data.push(resolve::prio_offset(fresh[i]) as! u64);
                i++;
            }
            qput(j);
            jobs++;
        }
        // The rounds before's descriptions, while the workers read these.
        collect();
        wait(jobs);
        stat(str("round ", rounds, " read"));
    }

    collect();
    stat("descriptions collected");
    // A PIE exports what the libraries the given ones need use or define as
    // well, as GNU ld, which reads them: round after round, the libraries
    // the last round's need, not read yet, until there are none.
    if opts.pie || opts.shlib_check {
        var known = dictionary<u64, bool> {};      // the libraries' names, given or needed
        for d in dsos { insert(known, hash(dso_text[d.name_at..d.name_at + d.name_len]), true); }
        var lib_paths: u8[:][>..] = [];           // the indirect libraries', by number
        var path_text: u8[>..] = [];
        var followed = 0;                          // of indirect
        var first = true;
        loop {
            var queued = 0;
            fn follow(d: DsoRec, needer: const u8[:]) {
                var origin = needer.len;
                while origin > 0 && needer[origin - 1] != '/' { origin--; }
                each_split(dso_text[d.needed_at..d.needed_at + d.needed_len], 0) {
                    if it.len > 0 && insert(known, hash(it), true) {
                        let at = path_text.len;
                        let fd = find_needed(it, opts.rpath_link, opts.rpath, dso_text[d.run_at..d.run_at + d.run_len],
                                             needer[..max(origin - 1, 0)], path_text);
                        if fd < 0 {
                            print("warning: ", it, ", needed by ", needer, ", not found (try using -rpath or -rpath-link)");
                        } else {
                            let path = path_text[at..];
                            var j = job(JOB_SHARED, fd, nshards, 0, 0, ld_file_size(fd), lib_paths.len, path);
                            j.refs = true;
                            j.indirect = true;
                            lib_paths.push(path);
                            qput(j);
                            queued++;
                        }
                    }
                };
            }
            if first {
                for d in dsos { follow(d, paths[resolve::prio_file(d.prio) - 1]); }
                first = false;
            }
            while followed < indirect.len {
                let d = indirect[followed];
                follow(d, lib_paths[d.prio as! i64]);
                followed++;
            }
            if queued == 0 { break; }
            stat(str(queued, " needed libraries queued"));
            wait(queued);
            collect();
        }
        stat(str(indirect.len, " libraries read that the given ones need"));
    }
    // A PIE copies the shared libraries' data its objects refer to directly
    // (gcc's code does; resolve::CMD_COPY): each shard says what it holds of
    // that, and every shard then marks what a library defines at those
    // addresses, aliases included, before it counts what it exports.
    if opts.pie {
        resolve::broadcast(resolve::CMD_COPY_KEYS, nshards);
        var pairs: u64[>..] = [];
        for k in nshards { pairs.append(qget<resolve::CopyKeys>().keys); }
        if pairs.len > 0 { resolve::send_copies(pairs, nshards); }
    }
    resolve::broadcast(resolve::CMD_FINISH, nshards);
    var counts: i64[>..] = [];
    let res = finish_resolution(nshards, paths, opts, counts);
    let tables = res.tables;
    let symbols = res.symbols;
    let undefined = res.undefined;
    let duplicates = res.duplicates;
    let shlib_undefined = res.shlib_undefined;
    let digest = res.digest;
    if opts.trace { print_members(paths, fds, members); }
    let resolved_ms = (clock_ns() - t0) / 1e6;
    // A shared library may leave symbols for the libraries it is loaded
    // with, unless asked not to.
    // And what given shared libraries use, nothing defines, is an error if
    // checked: by default, for an executable.
    let undefined_errors = (if opts.shared && !opts.no_undefined { 0 } else { undefined }) +
                           (if opts.shlib_check { shlib_undefined } else { 0 });
    if errors > 0 || undefined_errors > 0 || duplicates > 0 || opts.resolve_only {
        print(paths.len, " inputs, ", members.len, " archive members taken in ", rounds, " rounds; ", symbols,
              " global symbols, ", undefined, " undefined (", if opts.shlib_check { shlib_undefined } else { 0 },
              " that shared libraries use), ", duplicates, " defined twice; ", errors,
              " errors; digest ", digest);
        print(nworkers, " workers, ", nshards, " shards, ", resolved_ms, " ms");
        return errors == 0 && undefined_errors == 0 && duplicates == 0;
    }

    // What weld does not make yet: an executable that is not position-
    // independent but uses shared libraries, and a static PIE.
    if !dyn_out && dsos.len > 0 {
        print("an executable with shared libraries must be position-independent (-pie) for weld so far");
        return false;
    }
    if opts.pie && opts.interp.len == 0 {
        print("a PIE executable without a dynamic linker (static PIE) is not supported yet");
        return false;
    }
    stat("resolved");

    // Phase 3: the output, made early. Made now at the most it can take, rather
    // than once laid out, so that the workers, idle while main lays out, fault
    // its pages in meanwhile: the relocating workers' first writes to its pages
    // otherwise do, and cost them half their time. The bound takes every section
    // as kept, padded as most, the linker's own as large as the symbols could
    // make them; past it, the output is made when laid out, as without. Cut to
    // size then; removed if the link fails before. Only as much as it surely
    // takes is faulted in, the sections in no COMDAT group and a symbol table
    // entry for each global symbol: cutting off pages faulted in costs main as
    // much as faulting them in saved.
    let bound, surely = output_bounds(secs, objs, tables, nshards, symbols, dso_text.len + 16 * paths.len);
    var populating = 0;
    var populate_piece = 0;
    var made_early = false;
    defer { if made_early { ld_discard(); } }
    if !opts.resolve_only {
        let fd = ld_create_early(opts.output, bound as! i64);
        if fd >= 0 {
            made_early = true;
            // Two jobs, page-aligned halves of what the output surely
            // has: more, faulting at once, contend for the file's page
            // cache lock, and spinning on the hyperthreads beside main slows
            // its layout. A 210 MB output: 39 jobs of 4 MB took 248 ms, two 240, four
            // 243, one 252 (not done in time).
            let piece = (surely as! i64 / 2) & ~(layout::PAGE as! i64 - 1);
            populating = if piece > 0 { 2 } else { 0 };
            populate_piece = piece;
            for i in populating { qput(job(JOB_POPULATE, fd, 0, 0, i * piece, piece, 0, "the output")); }
        }
    }
    stat(str("output made, at most ", bound >> 20, " MB, ", (populating * populate_piece) >> 20, " MB of it faulted in"));

    // Phase 4: export and layout. Number the symbols, shard after shard.
    var base = 0;
    for k in nshards {
        resolve::command(k, resolve::CMD_EXPORT, base);
        resolve::send_merge(k, merge_counts[k]);     // which it merges while main goes on
        base += counts[k];
    }
    var defs: resolve::Def[>..] = [];
    defs.resize(symbols, resolve::Def { prio: 0, value: 0, size: 0, sym: 0, shndx: 0, kind: 0, stype: 0, need: 0,
                                        defined: false, vis: 0, bind: 0, referenced: false, strong: false, in_dso: false, gnu_hash: 0,
                                        name_len: 0, copied: false });
    for k in nshards {
        let d = qget<resolve::Defs>();
        var at = 0;
        for j in d.shard { at += counts[j]; }
        for e, j in d.defs { defs[at + j] = e; }
    }

    stat("definitions received");
    // Layout: objects in command-line order, their sections in order.
    sort(objs) { a, b => a.prio < b.prio };
    var index = ObjIndex { last_prio: 0xffffffffffffffff, last_at: 0, file_first: [] };
    index_objects(index, objs, paths.len);
    fn find(p: u64) -> i64 { find_object(index, objs, p) }
    var imports = 0;
    var npieces = 0;
    for &o in objs {
        o.imp_base = imports;
        imports += o.nsyms - o.first_global;
        o.piece_base = npieces;
        npieces += o.pieces;
    }
    stat("objects indexed");
    let dropped = leave_out_group_copies(nshards, objs, secs, index);

    stat("group copies left out");
    // The merged strings: each merge group one section after the rest of its
    // output section's, each shard's part of it in turn (merge.goose).
    var merged = Merged { at: [0; resolve::MAX_SHARDS], end: [0; resolve::MAX_SHARDS], data: [] };
    var mgroups: u64[>..] = [];          // the merge groups, ascending
    var part_at: u64[>..] = [];          // group gi's shard k's part: its offset in the group's section
    var merge_sec: i64[>..] = [];        // each group's section, in secs
    lay_out_merge_groups(nshards, secs, merged, mgroups, part_at, merge_sec);
    stat(str(mgroups.len, " merge groups, ", merged.data.len, " words of merged strings' places"));
    // Every section that goes in the output, in the order it goes there,
    // and each class's size: count[c] is where class c starts in sorted.
    var count: i64[layout::NCLASSES + 1] = [0; layout::NCLASSES + 1];
    var sorted: Placement[>..] = [];
    var outs: layout::Out[layout::NCLASSES] = [layout::Out { addr: 0, size: 0, align: 1 }; layout::NCLASSES];
    place_sections(objs, secs, merge_sec, count, sorted, outs);
    stat("sections placed");
    // Sections not loaded: each name an output section of its own (its
    // key), in which a section's address is its offset, as DWARF's
    // references between them count.
    let nkept = layout::KEPT_NONALLOC.len;
    var kept_start: u64[>..] = [];
    var kept_end: u64[>..] = [];
    var kept_align: u64[>..] = [];
    kept_start.resize(nkept, 0); kept_end.resize(nkept, 0); kept_align.resize(nkept, 1);
    var kept_seen: bool[>..] = [];
    kept_seen.resize(nkept, false);
    for x in sorted {
        if x.class != layout::NONALLOC { continue; }
        let s .= secs[x.sec];
        if !kept_seen[s.key] { kept_seen[s.key] = true; kept_start[s.key] = s.addr; }
        kept_end[s.key] = s.addr + s.size;
        kept_align[s.key] = max(kept_align[s.key], sec_align(s));
    }
    for &s in secs { if s.class == layout::NONALLOC { s.addr -= kept_start[s.key]; } }

    // Phase 5: the linker's own sections. Common symbols go at the end of .bss.
    // The linker's own sections go at the end of the output sections they belong
    // with: the GOT and .dynamic after .data.rel.ro, IFUNC and PLT stubs after
    // .text, the IFUNC stubs' slots after .data, the build ID after the notes, a
    // shared library's tables for the dynamic linker in a class of their own, as
    // are the merged property note and .eh_frame_hdr.
    //
    // In a shared library, a global symbol of default visibility is
    // exported, and preemptible: what is loaded first may define it in its
    // place, so references to it go through the GOT and the PLT. A symbol
    // a shared library defines, or none does, is imported.
    var addrs: u64[>..] = [];
    addrs.resize(symbols, 0);
    var status: u8[>..] = [];            // NOT_DYNAMIC, EXPORTED or IMPORTED
    status.resize(symbols, NOT_DYNAMIC);
    var preemptible: bool[>..] = [];
    preemptible.resize(symbols, false);
    var slot: i64[>..] = [];             // a symbol's GOT slot, or -1
    slot.resize(symbols, -1);
    var plt: i64[>..] = [];              // its PLT entry, or -1
    plt.resize(symbols, -1);
    var pair: i64[>..] = [];             // its general-dynamic TLS pair's first slot, or -1
    pair.resize(symbols, -1);
    var stub: i64[>..] = [];             // an IFUNC's stub, or -1
    stub.resize(symbols, -1);
    var nslots = 0;
    var nplt = 0;
    var nstubs = 0;
    var static_tls = false;              // initial-exec TLS in a shared library
    var exports_ifunc = false;           // which takes the GNU OS ABI, as an IFUNC stub does
    // The copies of shared libraries' data (CMD_COPY), at the end of .bss:
    // one an address in a library, its aliases sharing it, as large as the
    // largest of them and aligned as its address is, to 64 at most. The
    // first symbol at each is the one its R_X86_64_COPY names.
    var copy_size = dictionary<u64, u64> {};
    for &d in defs {
        if d.copied {
            let size .= get_or_insert(copy_size, resolve::copy_key(d.prio, d.value), 1);
            size = max(size, d.size);
        }
    }
    var copy_at = dictionary<u64, u64> {};
    var copy_first: i64[>..] = [];       // a copy's first symbol, by id
    for &d, id in defs {
        if d.copied {
            let key = resolve::copy_key(d.prio, d.value);
            let at = get(copy_at, key);
            if at { addrs[id] = at; continue; }
            let bss .= outs[layout::BSS];
            let align: u64 = if d.value == 0 { 64 } else { min((1 as u64) << ctz(d.value), 64) };
            bss.align = max(bss.align, align);
            addrs[id] = layout::align_up(bss.size, align);
            bss.size = addrs[id] + get_or_insert(copy_size, key, 1);
            insert(copy_at, key, addrs[id]);
            copy_first.push(id);
        }
    }
    for &d, id in defs {
        if d.defined && d.kind == resolve::COMMON {
            let bss .= outs[layout::BSS];
            bss.align = max(bss.align, d.value);
            addrs[id] = layout::align_up(bss.size, d.value);
            bss.size = addrs[id] + d.size;
        }
        if dyn_out {
            let from_object = d.defined && (d.kind == resolve::DEF || d.kind == resolve::WEAK || d.kind == resolve::COMMON ||
                                            d.kind == resolve::COMDAT);
            var kept = from_object;
            if from_object && d.kind != resolve::COMMON && d.shndx != elf::SHN_ABS {
                let o .= objs[find(d.prio)];
                kept = secs[o.sec_base + d.shndx].class != layout::DISCARD;
            }
            // An executable exports only what a shared library defines or
            // uses of it (as GNU ld does), or all with --export-dynamic; and
            // what it defines, nothing can preempt.
            if d.copied {                // defined here now, and the libraries use it
                status[id] = EXPORTED;
            } else if d.referenced && (!d.defined || d.kind == resolve::SHARED) {
                status[id] = IMPORTED;
                preemptible[id] = true;
            } else if kept && (d.vis == 0 || d.vis == 3) && (opts.shared || opts.export_dynamic || d.in_dso) {
                status[id] = EXPORTED;
                preemptible[id] = opts.shared && d.vis == 0 && d.stype != STT_GNU_IFUNC;
                exports_ifunc = exports_ifunc || d.stype == STT_GNU_IFUNC;
            }
        }
        let n = d.need;
        let tls = n & (reloc::NEED_TLS_GOT | reloc::NEED_IE_RELAXABLE) != 0;
        if n & (reloc::NEED_GOT | reloc::NEED_TLS_GOT) != 0 || (n & reloc::NEED_GOT_RELAXABLE != 0 && preemptible[id]) ||
           (n & reloc::NEED_PLT != 0 && preemptible[id]) || (opts.shared && tls) || (tls && preemptible[id]) {
            slot[id] = nslots;
            nslots++;
        }
        if opts.shared && tls { static_tls = true; }
        if n & reloc::NEED_PLT != 0 && preemptible[id] { plt[id] = nplt; nplt++; }
        if d.defined && d.stype == STT_GNU_IFUNC && resolve::rank(d.kind) > 1 { stub[id] = nstubs; nstubs++; }
    }
    // A general-dynamic TLS symbol's module and offset, and the
    // local-dynamic module's, are pairs of slots after the rest.
    var npairs = 0;
    if opts.shared {
        for &d, id in defs { if d.need & reloc::NEED_TLSGD != 0 { pair[id] = nslots + 2 * npairs; npairs++; } }
    }
    let tlsld_slot = nslots + 2 * npairs;
    let got_slots = tlsld_slot + (if opts.shared && any_tlsld { 2 } else { 0 });

    // The dynamic symbol table: imports first, then exports by .gnu.hash
    // bucket; .dynstr holds the libraries' and versions' names first.
    var dyn_index: u32[>..] = [];
    dyn_index.resize(symbols, 0);
    var dynstr: u8[>..] = [];
    dynstr.push(0);
    var needs: dynamic::Need[>..] = [];
    var versions: u16[>..] = [];         // each symbol's version index
    versions.resize(symbols, 1);
    var dyn_name: u32[>..] = [];
    dyn_name.resize(symbols, 0);
    var dynstr_prefix = 1;               // what of .dynstr main writes
    var export_hashes: u32[>..] = [];
    var ndyn = 1;
    var needed_at: u32[>..] = [];        // each shared library's name in .dynstr, once each name
    var soname_at: u32 = 0;
    var runpath_at: u32 = 0;
    if dyn_out {
        sort(dsos) { a, b => a.prio < b.prio };
        var used = dictionary<i64, bool> {};      // the libraries an import resolves to
        for &d, id in defs {
            if (status[id] == IMPORTED || d.copied) && d.kind == resolve::SHARED { insert(used, resolve::prio_file(d.prio), true); }
        }
        for d in dsos {
            let file = resolve::prio_file(d.prio);
            if given[file - 1].as_needed && !contains(used, file) { continue; }
            let name = dso_text[d.name_at..d.name_at + d.name_len];
            var seen = false;
            for at in needed_at { if elf::cstr(dynstr, at) == name { seen = true; } }
            if !seen { needed_at.push(dynstr.len as! u32); dynstr.append(name); dynstr.push(0); }
        }
        if opts.soname.len > 0 { soname_at = dynstr.len as! u32; dynstr.append(opts.soname); dynstr.push(0); }
        if opts.rpath.len > 0 { runpath_at = dynstr.len as! u32; dynstr.append(opts.rpath); dynstr.push(0); }
        // The versions imports need, of each library, numbered from 2.
        var need_of = dictionary<u64, i64> {};
        for &d, id in defs {
            if (status[id] != IMPORTED && !d.copied) || d.kind != resolve::SHARED || d.shndx < 2 { continue; }
            let file = resolve::prio_file(d.prio);
            let key: u64 = (file as! u64) << 16 | d.shndx;
            let known = get(need_of, key);
            if known { versions[id] = needs[known].index; continue; }
            var dso_at = -1;
            for x, i in dsos { if resolve::prio_file(x.prio) == file { dso_at = i; } }
            if dso_at < 0 { continue; }
            let x = dsos[dso_at];
            let vname = version_name(dso_text[x.ver_at..x.ver_at + x.ver_len], d.shndx);
            if vname.len == 0 { continue; }
            let name = dso_text[x.name_at..x.name_at + x.name_len];
            var file_at: u32 = 0;
            for at in needed_at { if elf::cstr(dynstr, at) == name { file_at = at; } }
            let index = (needs.len + 2) as! u16;
            needs.push(dynamic::Need { file: file_at, name: dynstr.len as! u32, hash: dynamic::elf_hash(vname), index: index });
            dynstr.append(vname); dynstr.push(0);
            insert(need_of, key, needs.len - 1);
            versions[id] = index;
        }
        sort(needs) { a, b => a.file < b.file || (a.file == b.file && a.index < b.index) };
        var strs_at = dynstr.len;
        for &d, id in defs {
            if status[id] == IMPORTED {
                dyn_index[id] = ndyn as! u32; ndyn++;
                dyn_name[id] = strs_at as! u32; strs_at += d.name_len + 1;
            }
        }
        var nexports = 0;
        for id in symbols { if status[id] == EXPORTED { nexports++; } }
        let nb = dynamic::buckets(nexports);
        var keyed: u64[>..] = [];        // bucket, then id: sorted as plain integers
        for &d, id in defs { if status[id] == EXPORTED { keyed.push(((d.gnu_hash % nb) as! u64) << 32 | id as! u64); } }
        sort(keyed) { a, b => a < b };
        for key in keyed {
            let id = (key & 0xffffffff) as! i64;
            dyn_index[id] = ndyn as! u32; ndyn++;
            dyn_name[id] = strs_at as! u32; strs_at += defs[id].name_len + 1;
            export_hashes.push(defs[id].gnu_hash);
        }
        dynstr_prefix = dynstr.len;
        dynstr.resize(strs_at, 0);       // the names themselves the shards write
    }
    let nimports = ndyn - 1 - export_hashes.len;
    var gnu_hash: u8[>..] = [];
    if dyn_out { gnu_hash.append(dynamic::gnu_hash(export_hashes, 1 + nimports)); }
    let version_r, nverneed = dynamic::version_r(needs);

    // Run-time relocations: main's own first (the GOT, the TLS pairs,
    // IFUNCs), then each object's, one for each of its R_X86_64_64.
    var rela_main = 0;
    var rela_objects = 0;
    if dyn_out {
        rela_main = got_slots + nstubs + copy_first.len;
        for &o in objs[1..] {
            o.rela_index = rela_main + rela_objects;
            rela_objects += o.abs64;
            o.rela_count = rela_main + rela_objects - o.rela_index;
        }
    }
    let ndynamic = 32 + needed_at.len;   // .dynamic's entries at most

    var own: u64[layout::NCLASSES] = [0; layout::NCLASSES];     // each class's size before the linker's own sections
    for c in layout::NCLASSES { own[c] = outs[c].size; }
    var extras: Extra[>..] = [];
    fn extra(class: u8, name: const u8[:], kind: u32, size: u64, align: u64, entsize: u64) -> u64 {
        let o .= outs[class];
        o.align = max(o.align, align);
        let at = layout::align_up(o.size, align);
        o.size = at + size;
        if size > 0 { extras.push(Extra { class: class, name: name, kind: kind, at: at, size: size, align: align, entsize: entsize }); }
        return at;
    }
    let property = property_note(and_features, isa_needed);
    var fdes = 0;
    if opts.eh_frame_hdr {
        for &o in objs { fdes += o.fdes; }
    }
    let note_size: u64 = if opts.build_id > 0 { 16 + layout::align_up(opts.build_id as! u64, 4) } else { 0 };
    let shared_size: u64 = if dyn_out { 1 } else { 0 };    // the dynamic tables' sizes, if any
    let property_at = extra(layout::PROPERTY, ".note.gnu.property", layout::SHT_NOTE, property.len as! u64, 8, 0);
    let build_id_at = extra(layout::NOTE, ".note.gnu.build-id", layout::SHT_NOTE, note_size, 4, 0);
    let interp_at = extra(layout::DYNAMIC_TABLES, ".interp", 1, if opts.pie { opts.interp.len as! u64 + 1 } else { 0 }, 1, 0);
    let hash_at = extra(layout::DYNAMIC_TABLES, ".gnu.hash", SHT_GNU_HASH, gnu_hash.len as! u64, 8, 0);
    let dynsym_at = extra(layout::DYNAMIC_TABLES, ".dynsym", SHT_DYNSYM, shared_size * 24 * ndyn as! u64, 8, 24);
    let dynstr_at = extra(layout::DYNAMIC_TABLES, ".dynstr", elf::SHT_STRTAB, shared_size * dynstr.len as! u64, 1, 0);
    let versym_at = extra(layout::DYNAMIC_TABLES, ".gnu.version", SHT_GNU_VERSYM, shared_size * 2 * ndyn as! u64, 2, 2);
    let verneed_at = extra(layout::DYNAMIC_TABLES, ".gnu.version_r", SHT_GNU_VERNEED, version_r.len as! u64, 8, 0);
    let rela_dyn_at = extra(layout::DYNAMIC_TABLES, ".rela.dyn", elf::SHT_RELA, 24 * (rela_main + rela_objects) as! u64, 8, 24);
    let irel_at = extra(layout::RODATA, ".rela.iplt", elf::SHT_RELA, (1 - shared_size) * 24 * nstubs as! u64, 8, 24);
    let eh_hdr_at = extra(layout::EH_FRAME_HDR, ".eh_frame_hdr", 1, if fdes > 0 { 12 + 8 * fdes as! u64 } else { 0 }, 4, 0);
    let stubs_at = extra(layout::TEXT, ".iplt", 1, 16 * nstubs as! u64, 16, 16);
    let plt_at = extra(layout::TEXT, ".plt", 1, 16 * nplt as! u64, 16, 16);
    let got_at = extra(layout::DATA_RELRO, ".got", 1, 8 * got_slots as! u64, 8, 8);
    let dynamic_at = extra(layout::DATA_RELRO, ".dynamic", SHT_DYNAMIC, shared_size * 16 * ndynamic as! u64, 8, 16);
    let igot_at = extra(layout::DATA, ".got.plt", 1, 8 * nstubs as! u64, 8, 8);

    stat("synthetic sections sized");
    let img = layout::assign(outs);
    let tables_at = outs[layout::DYNAMIC_TABLES].addr;
    let synth = Synthetic { got: outs[layout::DATA_RELRO].addr + got_at, igot: outs[layout::DATA].addr + igot_at,
                            stubs: outs[layout::TEXT].addr + stubs_at, irel: outs[layout::RODATA].addr + irel_at,
                            build_id: outs[layout::NOTE].addr + build_id_at, property: outs[layout::PROPERTY].addr + property_at,
                            eh_hdr: outs[layout::EH_FRAME_HDR].addr + eh_hdr_at, nslots: nslots,
                            nstubs: if dyn_out { 0 } else { nstubs },
                            plt: outs[layout::TEXT].addr + plt_at, hash: tables_at + hash_at, dynsym: tables_at + dynsym_at,
                            dynstr: tables_at + dynstr_at, versym: tables_at + versym_at, verneed: tables_at + verneed_at,
                            rela_dyn: tables_at + rela_dyn_at, dynamic: outs[layout::DATA_RELRO].addr + dynamic_at };
    let tp = if img.tls.memsz > 0 { img.tls.addr + layout::align_up(img.tls.memsz, img.tls_align) } else { 0 };
    for &s in secs { if s.class != layout::DISCARD && s.class != layout::NONALLOC { s.addr += outs[s.class].addr; } }
    // Where each group of sections a __start_ or __stop_ symbol names begins and ends.
    var groups = dictionary<u64, Range> {};
    for x in sorted {
        let s .= secs[x.sec];
        if !s.named { continue; }
        let r .= get_or_insert(groups, s.key, Range { start: s.addr, end: s.addr + s.size });
        r.start = min(r.start, s.addr);
        r.end = max(r.end, s.addr + s.size);
    }
    var resolvers: u64[>..] = [];       // each IFUNC's resolver, by stub
    resolvers.resize(nstubs, 0);
    var lost = 0;                        // symbols whose definitions were left out
    for &d, id in defs {
        if d.copied { addrs[id] += outs[layout::BSS].addr; continue; }                 // a copy, in .bss
        if !d.defined || d.kind == resolve::GROUP || d.kind == resolve::SHARED { continue; }    // imports: 0
        if d.kind == resolve::COMMON { addrs[id] += outs[layout::BSS].addr; continue; }
        if d.kind == resolve::PROVIDED { addrs[id] = linker_value(d.sym, outs, img, synth); continue; }
        if d.shndx == elf::SHN_ABS { addrs[id] = d.value; continue; }
        let o .= objs[find(d.prio)];
        let s .= secs[o.sec_base + d.shndx];
        if d.kind == resolve::START || d.kind == resolve::STOP {
            let r = get(groups, s.key);
            assert(r);
            addrs[id] = if d.kind == resolve::START { r.start } else { r.end };
            continue;
        }
        if s.class == layout::DISCARD { lost++; continue; }
        addrs[id] = s.addr + d.value;
        if stub[id] >= 0 {               // calls and address-taking go through the stub
            resolvers[stub[id]] = addrs[id];
            addrs[id] = synth.stubs + 16 * stub[id] as! u64;
        }
    }

    stat("addresses assigned");
    // Each object's imports and GOT slots, gathered by id from the occurrences.
    // Packed, as relocate unpacks them: its GOT slot and PLT entry, each
    // plus one (0 is none), in one value; for a shared library its dynamic
    // symbol index, general-dynamic TLS pair's first slot plus one, and
    // whether it is preemptible, in another.
    var imp: u64[>..] = [];
    imp.resize(imports, 0);
    var slots: u64[>..] = [];
    slots.resize(imports, 0);
    var dynx: u64[>..] = [];
    if dyn_out { dynx.resize(imports, 0); }
    for k in nshards {
        let m = qget<resolve::Occs>();
        for x in m.occs {
            let o .= objs[find(x.prio)];
            let at = o.imp_base + x.sym - o.first_global;
            imp[at] = addrs[x.id];
            slots[at] = ((slot[x.id] + 1) as! u64) | ((plt[x.id] + 1) as! u64) << 32;
            if dyn_out {
                dynx[at] = dyn_index[x.id] | ((pair[x.id] + 1) as! u64) << 32 |
                           (if preemptible[x.id] { reloc::PREEMPTIBLE } else { 0 });
            }
        }
    }
    let entry = imp[objs[0].imp_base + LINKER_DEFINED.len];
    let init_addr = imp[objs[0].imp_base + LINKER_DEFINED.len + 1];
    let fini_addr = imp[objs[0].imp_base + LINKER_DEFINED.len + 2];

    stat("imports gathered");

    // Phase 6: section headers, an output section per class that has bytes, the
    // linker's own sections apart, then the symbol table and its names.
    var shdrs: layout::Shdr[>..] = [];
    var shstrtab: u8[>..] = [];
    shstrtab.push(0);
    var shndx_of: u16[layout::NCLASSES] = [0; layout::NCLASSES];
    var dynsym_index: u32 = 0;
    var dynstr_index: u32 = 0;
    fn add_shdr(name: const u8[:], h: layout::Shdr) -> u16 {
        var x = h;
        x.name = shstrtab.len as! u32;
        shstrtab.append(name);
        shstrtab.push(0);
        shdrs.push(x);
        return shdrs.len as! u16;          // the null section header comes first
    }
    // The sections not loaded follow the loaded ones in the file.
    let kept_at = layout::align_up(img.file_size, 8);
    var kept_index: u16[>..] = [];
    kept_index.resize(nkept, 0);
    for c in 1..layout::NCLASSES {
        let o = outs[c];
        if c == layout::NONALLOC {
            for k in 1..nkept {
                if !kept_seen[k] { continue; }
                let name = layout::KEPT_NONALLOC[k];
                let strings = name == ".debug_str" || name == ".debug_line_str" || name == ".comment";
                kept_index[k] = add_shdr(name, layout::Shdr { name: 0, kind: 1, flags: if strings { 0x30 } else { 0 }, addr: 0,
                    offset: kept_at + kept_start[k], size: kept_end[k] - kept_start[k], link: 0, info: 0,
                    align: kept_align[k], entsize: if strings { 1 } else { 0 } });
            }
            continue;
        }
        if own[c] > 0 {
            shndx_of[c] = add_shdr(layout::NAMES[c], layout::Shdr { name: 0, kind: layout::KINDS[c], flags: layout::FLAGS[c],
                addr: o.addr, offset: o.addr - layout::BASE, size: own[c], link: 0, info: 0, align: o.align, entsize: 0 });
        }
        for x in extras {
            if x.class == c {
                let k = add_shdr(x.name, layout::Shdr { name: 0, kind: x.kind, flags: layout::FLAGS[c] | (if x.kind == elf::SHT_RELA { 0x40 } else { 0 }),
                    addr: o.addr + x.at, offset: o.addr + x.at - layout::BASE, size: x.size, link: 0, info: 0,
                    align: x.align, entsize: x.entsize });
                if own[c] == 0 { shndx_of[c] = k; }
                if x.kind == SHT_DYNSYM { dynsym_index = k; }
                if x.name == ".dynstr" { dynstr_index = k; }
            }
        }
    }
    // The dynamic tables' links: to .dynsym, or to .dynstr.
    for &h in shdrs {
        if h.kind == SHT_DYNSYM { h.link = dynstr_index; h.info = 1; }
        if h.kind == SHT_GNU_HASH || h.kind == SHT_GNU_VERSYM || (h.kind == elf::SHT_RELA && dyn_out) { h.link = dynsym_index; }
        if h.kind == SHT_GNU_VERNEED { h.link = dynstr_index; h.info = nverneed as! u32; }
        if h.kind == SHT_DYNAMIC { h.link = dynstr_index; }
    }

    // The symbol table: the null symbol, each object's locals, each shard's
    // hidden symbols, then each shard's globals; their names likewise.
    var nlocal: i64 = 1;
    var strs: i64 = 1;
    for &o in objs[1..] {
        o.sym_index = nlocal;
        o.str_index = strs;
        nlocal += o.abs_locals;
        strs += o.abs_strs;
        nlocal += o.locals;
        strs += o.local_strs;
    }
    var shard_local: i64[resolve::MAX_SHARDS] = [0; resolve::MAX_SHARDS];
    var shard_local_str: i64[resolve::MAX_SHARDS] = [0; resolve::MAX_SHARDS];
    for k in nshards { shard_local[k] = nlocal; shard_local_str[k] = strs; nlocal += tables[k].locals; strs += tables[k].local_strs; }
    var nsym = nlocal;
    var shard_global: i64[resolve::MAX_SHARDS] = [0; resolve::MAX_SHARDS];
    var shard_global_str: i64[resolve::MAX_SHARDS] = [0; resolve::MAX_SHARDS];
    for k in nshards { shard_global[k] = nsym; shard_global_str[k] = strs; nsym += tables[k].globals; strs += tables[k].global_strs; }
    let symtab_at = layout::align_up(kept_at + outs[layout::NONALLOC].size, 8);
    let strtab_at = symtab_at + 24 * nsym as! u64;
    let strtab_index = shdrs.len as! u32 + 2;
    add_shdr(".symtab", layout::Shdr { name: 0, kind: elf::SHT_SYMTAB, flags: 0, addr: 0, offset: symtab_at,
        size: 24 * nsym as! u64, link: strtab_index, info: nlocal as! u32, align: 8, entsize: 24 });
    add_shdr(".strtab", layout::Shdr { name: 0, kind: elf::SHT_STRTAB, flags: 0, addr: 0, offset: strtab_at,
        size: strs as! u64, link: 0, info: 0, align: 1, entsize: 0 });
    let shstrtab_at = strtab_at + strs as! u64;
    let shstrndx = add_shdr(".shstrtab", layout::Shdr { name: 0, kind: elf::SHT_STRTAB, flags: 0, addr: 0,
        offset: shstrtab_at, size: 0, link: 0, info: 0, align: 1, entsize: 0 });
    shdrs[shdrs.len - 1].size = shstrtab.len as! u64;
    let shoff = layout::align_up(shstrtab_at + shstrtab.len as! u64, 8);
    let file_size = shoff + 64 * (shdrs.len + 1) as! u64;
    let tls_start = img.tls.addr;
    stat("symbol table laid out");
    let laid_ms = (clock_ns() - t0) / 1e6;

    // Phase 7: writing. The headers and synthetic sections here, every object's
    // sections on the workers.
    let out = ld_create(opts.output, file_size as! i64);
    made_early = false;                  // it is the output now
    guard out >= 0 else { print("cannot create ", opts.output); return false; }
    var tail: u8[>..] = [];
    tail.append(shstrtab);
    for k in (shoff - shstrtab_at) as! i64 - shstrtab.len { tail.push(0); }
    layout::shdr(tail, layout::Shdr { name: 0, kind: 0, flags: 0, addr: 0, offset: 0, size: 0, link: 0, info: 0, align: 0, entsize: 0 });
    for h in shdrs { layout::shdr(tail, h); }
    let interp_addr = outs[layout::DYNAMIC_TABLES].addr + interp_at;
    if opts.pie {                        // the dynamic linker's name, in .interp
        var name: u8[>..] = [];
        name.append(opts.interp);
        name.push(0);
        guard put(out, (interp_addr - layout::BASE) as! i64, name, idsum) else { print("cannot write ", opts.output); return false; }
    }
    guard put(out, 0, layout::headers(img, outs, entry, shoff, shdrs.len + 1, shstrndx, nstubs > 0 || exports_ifunc, opts.relro,
                                      dyn_out, synth.dynamic, if dyn_out { 16 * ndynamic as! u64 } else { 0 }, interp_addr,
                                      if opts.pie { opts.interp.len as! u64 + 1 } else { 0 }), idsum) &&
          put(out, shstrtab_at as! i64, tail, idsum) else { print("cannot write ", opts.output); return false; }

    stat("headers written");
    // Each merged string's address, from the shards' answers, numbered by
    // object (piece_base) and through each; and where each shard's parts
    // go in the file.
    var piece_addr: u64[>..] = [];
    piece_addr.resize(npieces, 0);
    for k in nshards {
        let d = shard_part(merged, k);
        var at = 1 + 2 * d[0] as! i64;
        var oi = 0;                      // objects and runs alike by prio
        while at < d.len {
            let prio = d[at];
            let count = (d[at + 1] & 0xffffffff) as! i64;
            var gi = 0;
            while mgroups[gi] != d[at + 1] >> 32 { gi++; }
            at += 2;
            while objs[oi].prio < prio { oi++; }
            let first = objs[oi].piece_base;
            let a0 = secs[merge_sec[gi]].addr + part_at[gi * nshards + k];
            for e in d[at..at + count] { piece_addr[first + (e >> 32) as! i64] = a0 + (e & 0xffffffff); }
            at += count;
        }
        var parts: u64[>..] = [];
        for g, gi in mgroups {
            let s .= secs[merge_sec[gi]];
            let file = if s.class == layout::NONALLOC { kept_at + kept_start[s.key] + s.addr } else { s.addr - layout::BASE };
            parts.push(g);
            parts.push(file + part_at[gi * nshards + k]);
        }
        resolve::send_merge_at(k, parts);
    }
    // Each section's place, one value apiece in the order of secs: its
    // address, its output section's index in the top 16 bits; or NOT_PLACED.
    // Its file offset is its address plus its output section's delta, in a
    // table every relocation job carries (NOT_PLACED: no bytes in the file).
    var places: u64[>..] = [];
    places.resize(secs.len, reloc::NOT_PLACED);
    for &s, i in secs {
        if s.class == layout::DISCARD { continue; }
        let index: u64 = if s.class == layout::NONALLOC { kept_index[s.key] } else { shndx_of[s.class] };
        assert(s.addr >> 48 == 0);
        places[i] = s.addr | index << 48;
    }
    var deltas: u64[>..] = [];
    deltas.resize(shdrs.len + 1, reloc::NOT_PLACED);
    for c in 1..layout::NCLASSES {
        if c == layout::NONALLOC || shndx_of[c] == 0 { continue; }
        if c != layout::BSS && c != layout::TBSS { deltas[shndx_of[c]] = 0 - layout::BASE; }
    }
    for k in 1..nkept { if kept_seen[k] { deltas[kept_index[k]] = kept_at + kept_start[k]; } }
    stat(str("places of ", secs.len, " sections"));
    // A relocation job an object: fewer, larger jobs saved handoffs but
    // balanced the workers worse, and were slower.
    let reloc_jobs = objs.len - 1;
    for o in objs[1..] {
        let file = resolve::prio_file(o.prio);
        var j = job(JOB_RELOCATE, fds[file - 1], nshards, file, o.offset, o.size, 0, paths[file - 1]);
        j.out = out;
        j.fdes = fdes > 0;
        j.hash_id = idsum.on;
        j.shared = dyn_out;
        j.pie = opts.pie;
        j.data.append(places[o.sec_base..o.sec_base + o.nsecs]);
        let n = o.nsyms - o.first_global;
        j.data.append(imp[o.imp_base..o.imp_base + n]);
        j.data.append(slots[o.imp_base..o.imp_base + n]);
        if dyn_out { j.data.append(dynx[o.imp_base..o.imp_base + n]); }
        j.data.append(deltas);
        j.data.append(piece_addr[o.piece_base..o.piece_base + o.pieces]);
        j.at = RelocAt { symtab_at: symtab_at + 24 * o.sym_index as! u64, strtab_at: strtab_at,
                         str_index: o.str_index as! u64, tp: tp, tls_start: tls_start, got: synth.got,
                         plt: synth.plt,
                         rela_at: if dyn_out { synth.rela_dyn - layout::BASE + 24 * o.rela_index as! u64 } else { 0 },
                         rela_room: if dyn_out { o.rela_count as! u64 } else { 0 },
                         tlsld_got: if dyn_out { synth.got + 8 * tlsld_slot as! u64 } else { 0 },
                         ndeltas: deltas.len, npieces: o.pieces };
        qput(j);
    }
    stat(str(reloc_jobs, " jobs queued, ", imports, " imports"));
    // Each shard writes its symbols, given their values: after the
    // relocation jobs, which need none of them, while the workers relocate.
    var base_id = 0;
    for k in nshards {
        var vals: resolve::SymVal[>..] = [];
        for id in base_id..base_id + counts[k] {
            let d = defs[id];
            var v = resolve::SymVal { value: addrs[id], shndx: 0, stype: d.stype, dyn_index: dyn_index[id],
                                      dyn_name: dyn_name[id], version: versions[id] };
            if d.kind == resolve::SHARED && d.stype == STT_GNU_IFUNC { v.stype = 2; }    // an import is a FUNC to us
            if d.copied {                // a copy, in .bss
                v.shndx = shndx_of[layout::BSS];
            } else if !d.defined || d.kind == resolve::SHARED {
                v.value = 0;
            } else if d.kind == resolve::PROVIDED || d.kind == resolve::START || d.kind == resolve::STOP || d.shndx == elf::SHN_ABS {
                v.shndx = elf::SHN_ABS as! u16;
                v.stype = if d.kind == resolve::PROVIDED || d.kind == resolve::START || d.kind == resolve::STOP { 0 } else { d.stype };
            } else if d.kind == resolve::COMMON {
                v.shndx = shndx_of[layout::BSS];
                v.stype = 1;
            } else if d.kind != resolve::GROUP {
                let o .= objs[find(d.prio)];
                let sec .= secs[o.sec_base + d.shndx];
                if sec.class == layout::DISCARD { v.value = 0; }
                else {
                    v.shndx = shndx_of[sec.class];
                    if stub[id] >= 0 { v.value = resolvers[stub[id]]; }           // an IFUNC: its resolver
                    if d.stype == 6 { v.value = addrs[id] - tls_start; }         // TLS: from the segment's start
                }
            }
            vals.push(v);
        }
        let dt = if dyn_out { -(layout::BASE as! i64) } else { 0 };      // the dynamic tables' file offsets
        resolve::send_symtab(k, out, symtab_at as! i64, strtab_at as! i64, shard_local[k], shard_global[k],
                             shard_local_str[k], shard_global_str[k], dt + synth.dynsym as! i64, dt + synth.dynstr as! i64,
                             dt + synth.versym as! i64, idsum.on, vals);
        base_id += counts[k];
    }
    stat("symbol values sent");
    // The GOT, and in a shared library its run-time relocations, which
    // open .rela.dyn: a slot holds an address, or for TLS an offset, that
    // the dynamic linker sets where the symbol is preemptible.
    var got: u64[>..] = [];
    got.resize(got_slots, 0);
    var dynrel: u8[>..] = [];
    fn slot_at(i: i64) -> u64 { synth.got + 8 * i as! u64 }
    for &d, id in defs {
        let tls = d.need & (reloc::NEED_TLS_GOT | reloc::NEED_IE_RELAXABLE) != 0;
        if slot[id] >= 0 {
            let at = slot[id];
            if !dyn_out || (tls && !opts.shared && !preemptible[id]) { got[at] = if tls { addrs[id] - tp } else { addrs[id] }; }
            else if tls {
                if preemptible[id] { dynamic::rela(dynrel, slot_at(at), dynamic::R_X86_64_TPOFF64, dyn_index[id], 0); }
                else { dynamic::rela(dynrel, slot_at(at), dynamic::R_X86_64_TPOFF64, 0, addrs[id] - tls_start); }
            } else if preemptible[id] {
                dynamic::rela(dynrel, slot_at(at), dynamic::R_X86_64_GLOB_DAT, dyn_index[id], 0);
            } else {
                got[at] = addrs[id];
                dynamic::rela(dynrel, slot_at(at), dynamic::R_X86_64_RELATIVE, 0, addrs[id]);
            }
        }
        if pair[id] >= 0 {               // module, then offset in it
            let at = pair[id];
            dynamic::rela(dynrel, slot_at(at), dynamic::R_X86_64_DTPMOD64, if preemptible[id] { dyn_index[id] } else { 0 }, 0);
            if preemptible[id] { dynamic::rela(dynrel, slot_at(at + 1), dynamic::R_X86_64_DTPOFF64, dyn_index[id], 0); }
            else { got[at + 1] = addrs[id] - tls_start; }
        }
    }
    if opts.shared && any_tlsld { dynamic::rela(dynrel, slot_at(tlsld_slot), dynamic::R_X86_64_DTPMOD64, 0, 0); }
    for id in copy_first { dynamic::rela(dynrel, addrs[id], dynamic::R_X86_64_COPY, dyn_index[id], 0); }
    var bytes: u8[>..] = [];
    for v in got { layout::le(bytes, v, 8); }
    var ok = put(out, (synth.got - layout::BASE) as! i64, bytes, idsum);
    bytes.clear();
    for r in resolvers { layout::le(bytes, r, 8); }        // the stubs' slots, until IRELATIVE fills them
    ok = ok && put(out, (synth.igot - layout::BASE) as! i64, bytes, idsum);
    bytes.clear();
    for i in nstubs {                    // endbr64; jmp *slot(%rip); int3 to 16 bytes
        let at = synth.stubs + 16 * i as! u64;
        let target = synth.igot + 8 * i as! u64;
        let jmp: u8[6] = [0xf3, 0x0f, 0x1e, 0xfa, 0xff, 0x25];
        bytes.append(jmp);
        layout::le(bytes, target - (at + 10), 4);
        for k in 6 { bytes.push(0xcc); }
    }
    ok = ok && put(out, (synth.stubs - layout::BASE) as! i64, bytes, idsum);
    bytes.clear();
    for r, i in resolvers {              // R_X86_64_IRELATIVE: slot = resolver()
        if dyn_out { dynamic::rela(dynrel, synth.igot + 8 * i as! u64, dynamic::R_X86_64_IRELATIVE, 0, r); }
        else { dynamic::rela(bytes, synth.igot + 8 * i as! u64, dynamic::R_X86_64_IRELATIVE, 0, r); }
    }
    if !dyn_out { ok = ok && put(out, (synth.irel - layout::BASE) as! i64, bytes, idsum); }
    if dyn_out {
        bytes.clear();                   // PLT entries: endbr64; jmp *slot(%rip); int3 to 16 bytes
        var entries: i64[>..] = [];
        entries.resize(nplt, 0);
        for id in symbols { if plt[id] >= 0 { entries[plt[id]] = id; } }
        for id, i in entries {
            let at = synth.plt + 16 * i as! u64;
            let jmp: u8[6] = [0xf3, 0x0f, 0x1e, 0xfa, 0xff, 0x25];
            bytes.append(jmp);
            layout::le(bytes, slot_at(slot[id]) - (at + 10), 4);
            for k in 6 { bytes.push(0xcc); }
        }
        ok = ok && put(out, (synth.plt - layout::BASE) as! i64, bytes, idsum);
        guard dynrel.len / 24 <= rela_main else { print("more run-time relocations than counted"); return false; }
        ok = ok && put(out, (synth.rela_dyn - layout::BASE) as! i64, dynrel, idsum);
        ok = ok && put(out, (synth.hash - layout::BASE) as! i64, gnu_hash, idsum);
        ok = ok && put(out, (synth.verneed - layout::BASE) as! i64, version_r, idsum);
        ok = ok && put(out, (synth.dynstr - layout::BASE) as! i64, dynstr[..dynstr_prefix], idsum);   // the shards write the rest
        bytes.clear();
        for at in needed_at { dynamic::entry(bytes, dynamic::DT_NEEDED, at); }
        if opts.soname.len > 0 { dynamic::entry(bytes, dynamic::DT_SONAME, soname_at); }
        if opts.rpath.len > 0 { dynamic::entry(bytes, dynamic::DT_RUNPATH, runpath_at); }
        if init_addr != 0 { dynamic::entry(bytes, dynamic::DT_INIT, init_addr); }
        if fini_addr != 0 { dynamic::entry(bytes, dynamic::DT_FINI, fini_addr); }
        let ia = outs[layout::INIT_ARRAY];
        if ia.size > 0 { dynamic::entry(bytes, dynamic::DT_INIT_ARRAY, ia.addr); dynamic::entry(bytes, dynamic::DT_INIT_ARRAYSZ, ia.size); }
        let fa = outs[layout::FINI_ARRAY];
        if fa.size > 0 { dynamic::entry(bytes, dynamic::DT_FINI_ARRAY, fa.addr); dynamic::entry(bytes, dynamic::DT_FINI_ARRAYSZ, fa.size); }
        dynamic::entry(bytes, dynamic::DT_GNU_HASH, synth.hash);
        dynamic::entry(bytes, dynamic::DT_STRTAB, synth.dynstr);
        dynamic::entry(bytes, dynamic::DT_SYMTAB, synth.dynsym);
        dynamic::entry(bytes, dynamic::DT_STRSZ, dynstr.len as! u64);
        dynamic::entry(bytes, dynamic::DT_SYMENT, 24);
        if rela_main + rela_objects > 0 {
            dynamic::entry(bytes, dynamic::DT_RELA, synth.rela_dyn);
            dynamic::entry(bytes, dynamic::DT_RELASZ, 24 * (rela_main + rela_objects) as! u64);
            dynamic::entry(bytes, dynamic::DT_RELAENT, 24);
        }
        dynamic::entry(bytes, dynamic::DT_VERSYM, synth.versym);
        if nverneed > 0 {
            dynamic::entry(bytes, dynamic::DT_VERNEED, synth.verneed);
            dynamic::entry(bytes, dynamic::DT_VERNEEDNUM, nverneed as! u64);
        }
        let flags = (if opts.now { dynamic::DF_BIND_NOW } else { 0 }) | (if static_tls { dynamic::DF_STATIC_TLS } else { 0 });
        if flags != 0 { dynamic::entry(bytes, dynamic::DT_FLAGS, flags); }
        if opts.pie { dynamic::entry(bytes, dynamic::DT_DEBUG, 0); }    // for debuggers, which the dynamic linker sets
        let flags_1 = (if opts.now { dynamic::DF_1_NOW } else { 0 }) | (if opts.pie { dynamic::DF_1_PIE } else { 0 });
        if flags_1 != 0 { dynamic::entry(bytes, dynamic::DT_FLAGS_1, flags_1); }
        dynamic::entry(bytes, dynamic::DT_NULL, 0);
        guard bytes.len <= 16 * ndynamic else { print("more .dynamic entries than counted"); return false; }
        ok = ok && put(out, (synth.dynamic - layout::BASE) as! i64, bytes, idsum);
    }
    ok = ok && put(out, (synth.property - layout::BASE) as! i64, property, idsum);
    if note_size > 0 {                   // the build ID's note, its ID zeros until the file is hashed
        bytes.clear();
        layout::le(bytes, 4, 4); layout::le(bytes, opts.build_id as! u64, 4); layout::le(bytes, 3, 4);
        bytes.append("GNU\x00");
        ok = ok && put(out, (synth.build_id - layout::BASE) as! i64, bytes, idsum);
    }
    if !ok { print("cannot write ", opts.output); errors++; }
    stat("relocation jobs queued");
    wait(reloc_jobs + populating);
    for k in nshards {
        let d = qget<resolve::SymtabDone>();
        if !d.ok { print("cannot write the symbol table"); errors++; }
        idsum.a += d.ida;
        idsum.b += d.idb;
    }
    if fdes > 0 {                        // each relocation job sent its FDEs' starts
        var table: u64[>..] = [];
        for i in reloc_jobs {
            let m = qget<Fdes>();
            table.append(m.pairs);
        }
        let ok_hdr = put(out, (synth.eh_hdr - layout::BASE) as! i64,
                               eh_frame_hdr(table, synth.eh_hdr, outs[layout::EH_FRAME].addr, img.load[1].addr,
                                            img.load[1].addr + img.load[1].memsz), idsum);
        if !ok_hdr { print("cannot write ", opts.output); errors++; }
    }
    if note_size > 0 && errors == 0 {
        let id = build_id(idsum, file_size as! i64, opts);
        if !ld_pwrite(out, (synth.build_id + 16 - layout::BASE) as! i64, id) { print("cannot write ", opts.output); errors++; }
    }
    stat("written");
    ld_close(out);
    let ms = (clock_ns() - t0) / 1e6;
    if lost > 0 { print(lost, " symbols are defined only in sections that were left out"); errors++; }
    if !opts.quiet || opts.stats {       // a linker as a build runs it says nothing, unless asked
        print(opts.output, ": ", objs.len - 1, " objects (", members.len, " from archives), ", symbols, " global symbols, ",
              file_size, " bytes (", dropped, " in duplicate COMDAT groups left out); resolved ", resolved_ms, " ms, laid out ", laid_ms, " ms, written ", ms,
              " ms; ", nworkers, " workers");
    }
    if errors == 0 { ld_notify(); }      // the rest, out of the parent's time (ld_fork)
    ld_finish();
    return errors == 0;
}

// What a .note.gnu.property section says: the x86 features (IBT, SHSTK)
// all its code has, and the x86 ISA levels it needs.
let GNU_PROPERTY_X86_FEATURE_1_AND: u64 = 0xc0000002;
let GNU_PROPERTY_X86_ISA_1_NEEDED: u64 = 0xc0008002;
fn properties(b: const u8[:]) -> u32, u32 {
    var features: u32 = 0;
    var isa: u32 = 0;
    var at = 0;
    while at + 12 <= b.len {
        let namesz = eh::u32at(b, at) as! i64;
        let descsz = eh::u32at(b, at + 4) as! i64;
        let kind = eh::u32at(b, at + 8);
        let desc = at + 12 + ((namesz + 3) & ~3);
        guard desc + descsz <= b.len else { break; }
        if kind == 5 && namesz == 4 && b[at + 12..at + 16] == "GNU\x00" {
            var p = desc;
            while p + 8 <= desc + descsz {
                let pr = eh::u32at(b, p);
                let n = eh::u32at(b, p + 4) as! i64;
                if p + 8 + n > desc + descsz { break; }
                if n == 4 && pr == GNU_PROPERTY_X86_FEATURE_1_AND { features = eh::u32at(b, p + 8) as! u32; }
                if n == 4 && pr == GNU_PROPERTY_X86_ISA_1_NEEDED { isa = eh::u32at(b, p + 8) as! u32; }
                p += 8 + ((n + 7) & ~7);
            }
        }
        at = desc + ((descsz + 7) & ~7);
    }
    return features, isa;
}

// The output's .note.gnu.property: the features every input has, the ISA
// levels any needs; empty if both are none.
fn property_note(features: u32, isa: u32) -> u8[>..] {
    var out: u8[>..] = [];
    let n: u64 = (if features != 0 { 16 as u64 } else { 0 }) + (if isa != 0 { 16 as u64 } else { 0 });
    if n == 0 { return out; }
    layout::le(out, 4, 4); layout::le(out, n, 4); layout::le(out, 5, 4);
    out.append("GNU\x00");
    if features != 0 { layout::le(out, GNU_PROPERTY_X86_FEATURE_1_AND, 4); layout::le(out, 4, 4); layout::le(out, features, 4); layout::le(out, 0, 4); }
    if isa != 0 { layout::le(out, GNU_PROPERTY_X86_ISA_1_NEEDED, 4); layout::le(out, 4, 4); layout::le(out, isa, 4); layout::le(out, 0, 4); }
    return out;
}

// .eh_frame_hdr at hdr: a pointer to .eh_frame, then the FDEs of code in
// [lo, hi), sorted by where the code starts, as pairs of offsets from hdr.
// FDEs of left-out code point at 0 and are left out.
fn eh_frame_hdr(pairs: const u64[:], hdr: u64, eh_frame: u64, lo: u64, hi: u64) -> u8[>..] {
    var entries: Pair[>..] = [];
    for i in pairs.len / 2 {
        let pc = pairs[2 * i];
        if pc >= lo && pc < hi { entries.push(Pair { pc: pc, fde: pairs[2 * i + 1] }); }
    }
    sort(entries) { a, b => a.pc < b.pc || (a.pc == b.pc && a.fde < b.fde) };
    var out: u8[>..] = [];
    let head: u8[4] = [1, 0x1b, 0x03, 0x3b];
    out.append(head);     // version; pcrel sdata4; udata4 count; datarel sdata4 table
    layout::le(out, eh_frame - (hdr + 4), 4);
    layout::le(out, entries.len as! u64, 4);
    for e in entries { layout::le(out, e.pc - hdr, 4); layout::le(out, e.fde - hdr, 4); }
    return out;
}
struct Pair { pc: u64, fde: u64 }

// The build ID: as many bytes as the kind given asks for, from the sum of
// every write's XXH3 (xxh3::IdSum), or random for uuid, or as given in hex.
fn build_id(sum: const xxh3::IdSum&, size: i64, opts: const Options&) -> u8[>..] {
    var id: u8[>..] = [];
    if opts.build_id_given.len > 0 { id.append(opts.build_id_given); return id; }
    if opts.build_id_uuid {
        while id.len < opts.build_id { layout::le(id, random_seed(), 8); }
        id.resize(opts.build_id, 0);
        id[6] = (id[6] & 0x0f) | 0x40;               // version 4
        id[8] = (id[8] & 0x3f) | 0x80;               // RFC 4122 variant
        return id;
    }
    return xxh3::id(sum.a, sum.b, size, opts.build_id);
}

// Each member taken, as path(name), in command-line and archive order.
fn print_members(paths: const u8[:][:], fds: const i32[:], members: u64[>..]&) {
    sort(members) { a, b => a < b };
    var longnames: u8[>..] = [];
    var hdr: u8[>..] = [];
    var out: u8[>..] = [];
    var file = -1;
    for x in members {
        let f = resolve::prio_file(x);
        let fd = fds[f - 1];
        if f != file {          // the archive's long-name table follows its symbol index
            file = f;
            longnames.clear();
            var pos = ar::MAGIC.len;
            for k in 2 {
                hdr.clear();
                if !ld_pread(fd, pos, ar::HDR_SIZE, hdr) { break; }
                let raw, size, ok = ar::parse_header(hdr);
                if !ok { break; }
                if starts_with(raw, "// ") { ld_pread(fd, pos + ar::HDR_SIZE, size, longnames); break; }
                pos = ar::next_header(pos + ar::HDR_SIZE, size);
            }
        }
        hdr.clear();
        ld_pread(fd, resolve::prio_offset(x), ar::HDR_SIZE + 64, hdr);
        let raw, size, ok = ar::parse_header(hdr);
        let name, _, named = ar::resolve(raw, hdr[ar::HDR_SIZE..], longnames);
        format(out, paths[f - 1], "(", name, ")\n");
    }
    write_stdout(out);
}
