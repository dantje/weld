// weld's commands for looking at inputs rather than linking them: dump
// (symbol tables, as readelf -sW prints them), scan (read every object and
// archive member on every core, timed) and hash (XXH3 of a file's prefixes,
// which test.py checks against libxxhash).
import std;
import os;
import .elf;
import .archive;
import .xxh3;

fn type_name(out: u8[>..]&, t: u8) {
    let names = ["NOTYPE", "OBJECT", "FUNC", "SECTION", "FILE", "COMMON", "TLS"];
    if t < 7 { out.append(names[t]); } else if t == 10 { out.append("IFUNC"); }
    else { format(out, "<OS specific>: ", t); }
}

fn bind_name(out: u8[>..]&, b: u8) {
    let names = ["LOCAL", "GLOBAL", "WEAK"];
    if b < 3 { out.append(names[b]); } else if b == 10 { out.append("UNIQUE"); }
    else { format(out, "<OS specific>: ", b); }
}

fn pad_right(out: u8[>..]&, s: u8[:], width: i64) {
    out.append(s);
    for k in s.len..width { out.push(' '); }
}

fn pad_to(out: u8[>..]&, len: i64) { while out.len < len { out.push(' '); } }

fn pad_left(out: u8[>..]&, s: u8[:], width: i64) {
    for k in s.len..width { out.push(' '); }
    out.append(s);
}

fn dump_symbols(out: u8[>..]&, o: const elf::Object&) {
    if o.symtab.len == 0 { return; }
    let n = elf::nsymbols(o);
    let symtab = elf::section(o, o.symtab_index);
    format(out, "\nSymbol table '", elf::section_name(o, symtab), "' contains ", n,
           if n == 1 { " entry" } else { " entries" }, ":\n");
    out.append("   Num:    Value          Size Type    Bind   Vis      Ndx Name\n");
    for i in n {
        let s = elf::symbol(o, i);
        pad_left(out, str(i), 6);
        out.append(": ");
        format_uint(out, s.value, 16, 16, '0');
        out.push(' ');
        if s.size < 100000 { pad_left(out, str(s.size), 5); } else { format(out, "0x"); format_uint(out, s.size, 16, 0, '0'); }
        out.push(' ');
        var col = out.len;
        type_name(out, elf::stype(s));
        pad_to(out, col + 7);
        out.push(' ');
        col = out.len;
        bind_name(out, elf::bind(s));
        pad_to(out, col + 6);
        out.push(' ');
        let vis = ["DEFAULT", "INTERNAL", "HIDDEN", "PROTECTED"];
        pad_right(out, vis[elf::visibility(s)], 7);
        out.push(' ');
        let shndx = elf::symbol_section(o, i, s);
        let ndx = if shndx == elf::SHN_UNDEF { str("UND") } else if shndx == elf::SHN_ABS { str("ABS") }
                  else if shndx == elf::SHN_COMMON { str("COM") } else { str(shndx) };
        pad_left(out, ndx, 4);
        out.push(' ');
        if elf::stype(s) == 3 && s.name == 0 && shndx < elf::SHN_LORESERVE {
            let name = elf::section_name(o, elf::section(o, shndx));
            out.append(name[..min(name.len, 256)]);     // readelf's limit
        } else {
            out.append(elf::symbol_name(o, s));
        }
        out.push('\n');
    }
}

fn dump_object(out: u8[>..]&, label: u8[:], data: const u8[:]) -> bool {
    let o, err = elf::open(data);
    if err.len > 0 { print(label, ": ", err); return false; }
    dump_symbols(out, o);
    return true;
}

fn dump(path: u8[:]) -> bool {
    var data: u8[>..] = [];
    guard read_file(path, data) else { print("cannot read ", path); return false; }
    var out: u8[>..] = [];
    var ok = true;
    if ar::is_archive(data) {
        let err = ar::check(data);
        if err.len > 0 { print(path, ": ", err); return false; }
        ar::each_member(data) {
            format(out, "\nFile: ", path, "(", it.name, ")\n");
            if !dump_object(out, it.name, it.data) { ok = false; }
        };
    } else {
        ok = dump_object(out, path, data);
    }
    write_stdout(out);
    return ok;
}

// What reading a set of inputs found; a worker's share, or the sum.
struct Stats { objects: i64, sections: i64, symbols: i64, globals: i64, relocs: i64,
               bytes: i64, errors: i64, digest: u64 }

fn add(a: Stats&, b: Stats) {
    a.objects += b.objects; a.sections += b.sections; a.symbols += b.symbols; a.globals += b.globals;
    a.relocs += b.relocs; a.bytes += b.bytes; a.errors += b.errors; a.digest ^= b.digest;
}

// Everything phase 1 of a link reads in an object: each section, each
// relocation table's size, and each global symbol's name and hash.
fn scan_object(st: Stats&, label: u8[:], data: const u8[:]) {
    let o, err = elf::open(data);
    if err.len > 0 { print(label, ": ", err); st.errors++; return; }
    st.objects++;
    let ns = elf::nsections(o);
    st.sections += ns;
    for i in 1..ns {
        let s = elf::section(o, i);
        if s.kind == elf::SHT_RELA { st.relocs += elf::nrelas(s); }
    }
    let n = elf::nsymbols(o);
    st.symbols += n;
    for i in o.first_global..n {
        let s = elf::symbol(o, i);
        st.globals++;
        st.digest ^= hash(elf::symbol_name(o, s)) ^ (elf::symbol_section(o, i, s));
    }
}

// The most a job reads, unless one archive member is larger: big enough
// that a job outweighs its message, small enough that a large archive
// spreads over every worker and a worker's buffer stays in cache.
let CHUNK = 4 << 20;

// A range of an input for a worker to read: a whole object, or a run of
// whole archive members. fd -1 tells a worker to stop.
struct ScanJob { fd: i32, members: bool, offset: i64, size: i64, path: u8[varint] }

thread_fn scan_worker() {
    var st = default<Stats>();
    var buf: u8[>..] = [];             // reused: its pages are touched once
    loop {
        let job = qget<ScanJob>();
        guard job.fd >= 0 else { break; }
        buf.clear();
        if !ld_pread(job.fd, job.offset, job.size, buf) { print("cannot read ", job.path); st.errors++; continue; }
        st.bytes += buf.len;
        if job.members {
            let whole = ar::each_member_in(buf, job.offset) { scan_object(st, it.name, it.data); };
            if !whole { print(job.path, ": bad archive member in ", job.offset, "..", job.offset + job.size); st.errors++; }
        } else {
            scan_object(st, job.path, buf);
        }
    }
    qput(st);
}

// Queues an input as jobs: an archive as runs of members up to CHUNK
// bytes, found by reading each member header alone, its symbol index and
// long-name table left out. The number of errors.
fn queue_input(path: u8[:], fd: i32) -> i64 {
    let size = ld_file_size(fd);
    var hdr: u8[>..] = [];
    guard size >= 0 && ld_pread(fd, 0, min(size, ar::MAGIC.len), hdr) else { print("cannot read ", path); return 1; }
    if !ar::is_archive(hdr) {
        qput(ScanJob { fd: fd, members: false, offset: 0, size: size, path: path });
        return 0;
    }
    var start = ar::MAGIC.len;
    var pos = start;
    while pos < size {
        hdr.clear();
        guard ld_pread(fd, pos, min(ar::HDR_SIZE, size - pos), hdr) else { print("cannot read ", path); return 1; }
        let raw, msize, ok = ar::parse_header(hdr);
        guard ok && msize <= size - pos - ar::HDR_SIZE else { print(path, ": bad member header at ", pos); return 1; }
        let end = min(ar::next_header(pos + ar::HDR_SIZE, msize), size);
        if start == pos && (ar::is_special(raw) || starts_with(raw, "// ")) { start = end; }
        else if end - start >= CHUNK {
            qput(ScanJob { fd: fd, members: true, offset: start, size: end - start, path: path });
            start = end;
        }
        pos = end;
    }
    if start < size { qput(ScanJob { fd: fd, members: true, offset: start, size: size - start, path: path }); }
    return 0;
}

fn scan(paths: u8[:][:]) -> bool {
    let t0 = clock_ns();
    let n = max(1, hardware_threads());
    var ids: i64[>..] = [];
    for i in n { ids.push(thread_spawn(scan_worker)); }     // they read while main plans
    var total = default<Stats>();
    var fds: i32[>..] = [];
    for p in paths {
        let fd = ld_open(p);
        if fd < 0 { print("cannot open ", p); total.errors++; continue; }
        fds.push(fd);
        total.errors += queue_input(p, fd);
    }
    for i in n { qput(ScanJob { fd: -1, members: false, offset: 0, size: 0, path: "" }); }
    for i in n { add(total, qget<Stats>()); }
    for id in ids { thread_wait(id); }
    for fd in fds { ld_close(fd); }
    let ms = (clock_ns() - t0) as f64 / 1e6;
    print(paths.len, " files, ", total.bytes, " bytes, ", total.objects, " objects, ", total.sections,
          " sections, ", total.symbols, " symbols (", total.globals, " global), ", total.relocs,
          " relocations, ", total.errors, " errors; digest ", total.digest);
    print(n, " threads, ", ms, " ms, ", (total.bytes / 1e6) / (ms / 1e3), " MB/s");
    return total.errors == 0;
}

// Prints the XXH3 of each prefix of path given by length.
fn hash_prefixes(path: const u8[:], lengths: u8[:][:]) -> bool {
    var data: u8[>..] = [];
    guard read_file(path, data) else { print("cannot read ", path); return false; }
    for s in lengths {
        let n, ok = parse_int(s, 10);
        guard ok && n >= 0 && n <= data.len else { print("not a length within the file: ", s); return false; }
        print(xxh3::hash(data[..n]));
    }
    return true;
}
