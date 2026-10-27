// Shared libraries as inputs: the symbols one defines, from its dynamic
// symbol table, and the name it is needed by (DT_SONAME). Only the ELF
// header, the section headers and the sections that say these are read,
// with pread, since a library can carry hundreds of megabytes of debugging
// information besides.
namespace dso;
import std;
import .elf;

let ET_DYN: u16 = 3;
let SHT_DYNAMIC: u32 = 6;
let SHT_DYNSYM: u32 = 11;
let SHT_GNU_VERSYM: u32 = 0x6fffffff;
let SHT_GNU_VERDEF: u32 = 0x6ffffffd;
let DT_NEEDED: u64 = 1;
let DT_SONAME: u64 = 14;
let DT_RPATH: u64 = 15;
let DT_RUNPATH: u64 = 29;
let VERSYM_HIDDEN: u16 = 0x8000;

extern fn ld_pread(fd: i32, offset: i64, size: i64, out: u8[>..]&) -> bool;

// Where a library's tables are in buf, which read_tables filled.
struct Tables { dynsym_at: i64, dynsym_len: i64, dynstr_at: i64, dynstr_len: i64, versym_at: i64, versym_len: i64,
                verdef_at: i64, verdef_len: i64, soname_at: i64, soname_len: i64, dynamic_at: i64, dynamic_len: i64 }

fn in_file(s: elf::Section, size: i64) -> bool { elf::in_range(s.offset, s.size, size) }

// Reads the library at fd, size bytes, into buf: its section headers, then
// the tables. Empty if it is one; else what is wrong.
fn read_tables(fd: i32, size: i64, buf: u8[>..]&, t: Tables&) -> u8[>..] {
    guard size >= elf::EHDR_SIZE && ld_pread(fd, 0, elf::EHDR_SIZE, buf) else { return str("too short for an ELF header"); }
    let h = buf[..elf::EHDR_SIZE];
    guard h[0] == 0x7f && h[1] == 'E' && h[2] == 'L' && h[3] == 'F' && h[4] == 2 && h[5] == 1 else { return str("not ELF64 little-endian"); }
    guard elf::u16le(h, 16) == ET_DYN else { return str("not a shared library"); }
    guard elf::u16le(h, 18) == elf::EM_X86_64 else { return str("not x86-64"); }
    let shoff = elf::u64le(h, 40);
    let shnum = elf::u16le(h, 60) as i64;
    guard shnum > 0 && elf::u16le(h, 58) as i64 == elf::SHDR_SIZE && elf::in_range(shoff, (shnum * elf::SHDR_SIZE) as! u64, size) else {
        return str("no section headers");
    }
    let hdrs_at = buf.len;
    guard ld_pread(fd, shoff as! i64, shnum * elf::SHDR_SIZE, buf) else { return str("cannot read section headers"); }
    var dynsym = -1;
    var versym = -1;
    var dynamic = -1;
    var verdef = -1;
    for i in shnum {
        let s = elf::decode_section(buf[hdrs_at + i * elf::SHDR_SIZE..hdrs_at + (i + 1) * elf::SHDR_SIZE]);
        if s.kind == SHT_DYNSYM { dynsym = i; }
        if s.kind == SHT_GNU_VERSYM { versym = i; }
        if s.kind == SHT_DYNAMIC { dynamic = i; }
        if s.kind == SHT_GNU_VERDEF { verdef = i; }
    }
    guard dynsym >= 0 else { return str("no dynamic symbol table"); }
    fn header(i: i64) -> elf::Section { elf::decode_section(buf[hdrs_at + i * elf::SHDR_SIZE..hdrs_at + (i + 1) * elf::SHDR_SIZE]) }
    let sym = header(dynsym);
    guard in_file(sym, size) && sym.size % elf::SYM_SIZE == 0 && sym.link > 0 && sym.link < shnum else {
        return str("bad dynamic symbol table");
    }
    let str_s = header(sym.link);
    guard in_file(str_s, size) && str_s.size > 0 else { return str("bad dynamic string table"); }
    t.dynsym_at = buf.len; t.dynsym_len = sym.size as! i64;
    guard ld_pread(fd, sym.offset as! i64, t.dynsym_len, buf) else { return str("cannot read the dynamic symbol table"); }
    t.dynstr_at = buf.len; t.dynstr_len = str_s.size as! i64;
    guard ld_pread(fd, str_s.offset as! i64, t.dynstr_len, buf) && buf[buf.len - 1] == 0 else { return str("bad dynamic string table"); }
    t.versym_at = 0; t.versym_len = 0;
    if versym >= 0 {
        let v = header(versym);
        guard in_file(v, size) && v.size == (t.dynsym_len / elf::SYM_SIZE * 2) as! u64 else { return str("bad .gnu.version"); }
        t.versym_at = buf.len; t.versym_len = v.size as! i64;
        guard ld_pread(fd, v.offset as! i64, t.versym_len, buf) else { return str("cannot read .gnu.version"); }
    }
    t.verdef_at = 0; t.verdef_len = 0;
    if verdef >= 0 {
        let v = header(verdef);
        guard in_file(v, size) else { return str("bad .gnu.version_d"); }
        t.verdef_at = buf.len; t.verdef_len = v.size as! i64;
        guard ld_pread(fd, v.offset as! i64, t.verdef_len, buf) else { return str("cannot read .gnu.version_d"); }
    }
    t.soname_at = 0; t.soname_len = 0; t.dynamic_at = 0; t.dynamic_len = 0;
    if dynamic >= 0 {
        let d = header(dynamic);
        guard in_file(d, size) else { return str("bad .dynamic"); }
        let at = buf.len;
        guard ld_pread(fd, d.offset as! i64, (d.size as! i64) / 16 * 16, buf) else { return str("cannot read .dynamic"); }
        t.dynamic_at = at;
        t.dynamic_len = buf.len - at;
        var k = at;
        while k + 16 <= buf.len {
            let tag = elf::u64le(buf[k..k + 16], 0);
            if tag == 0 { break; }
            if tag == DT_SONAME {
                let off = elf::u64le(buf[k..k + 16], 8);
                guard off < t.dynstr_len as u64 else { return str("bad DT_SONAME"); }
                let names = buf[t.dynstr_at..t.dynstr_at + t.dynstr_len];
                let start = off as! i64;
                let rest = names[start..];
                t.soname_at = t.dynstr_at + off as! i64;
                t.soname_len = find_any(rest, elf::NUL);
            }
            k += 16;
        }
    }
    return [];
}

// F(index, name) for each version the library defines, its own name, the
// one of index 1, among them. Stops at anything malformed.
fn each_version<F>(buf: const u8[:], t: const Tables&) {
    let d = buf[t.verdef_at..t.verdef_at + t.verdef_len];
    let names = buf[t.dynstr_at..t.dynstr_at + t.dynstr_len];
    var at = 0;
    while at + 20 <= d.len {
        let index = elf::u16le(d[at..at + 20], 4);
        let aux = elf::u32le(d[at..at + 20], 12) as! i64;
        let next = elf::u32le(d[at..at + 20], 16) as! i64;
        if aux > 0 && at + aux + 8 <= d.len {
            let name = elf::u32le(d[at + aux..at + aux + 8], 0);
            if (name as i64) < names.len { F(index, elf::cstr(names, name)); }
        }
        if next == 0 { break; }
        at += next;
    }
}

// F(symbol index, symbol, name, version index) for each symbol the library defines for a
// reference with no version: global or weak, defined, and of the default
// version where it has versions (memcpy@@GLIBC_2.14, not the hidden
// memcpy@GLIBC_2.2.5).
fn each_definition<F>(buf: const u8[:], t: const Tables&) {
    let syms = buf[t.dynsym_at..t.dynsym_at + t.dynsym_len];
    let names = buf[t.dynstr_at..t.dynstr_at + t.dynstr_len];
    for i in 1..t.dynsym_len / elf::SYM_SIZE {
        let s = elf::decode_symbol(syms[i * elf::SYM_SIZE..(i + 1) * elf::SYM_SIZE]);
        let bind = elf::bind(s);
        if s.shndx as u32 == elf::SHN_UNDEF || !(bind == 1 || bind == 2 || bind == 10) { continue; }
        var version: u16 = 1;
        if t.versym_len > 0 {
            version = elf::u16le(buf[t.versym_at + 2 * i..t.versym_at + 2 * i + 2], 0);
            if version & VERSYM_HIDDEN != 0 || version == 0 { continue; }
        }
        if s.name as i64 >= names.len { continue; }
        F(i, s, elf::cstr(names, s.name), version);
    }
}

// Calls F with each string of .dynamic's entries of tag: the names of the
// libraries it needs (DT_NEEDED), say. Leaves out what is malformed.
fn each_dynamic_string<F>(buf: const u8[:], t: const Tables&, tag: u64) {
    let d = buf[t.dynamic_at..t.dynamic_at + t.dynamic_len];
    let names = buf[t.dynstr_at..t.dynstr_at + t.dynstr_len];
    var k = 0;
    while k + 16 <= d.len {
        let at = elf::u64le(d[k..k + 16], 0);
        if at == 0 { break; }
        let off = elf::u64le(d[k..k + 16], 8);
        if at == tag && off < names.len as u64 { F(elf::cstr(names, off as! u32)); }
        k += 16;
    }
}

// F(name) for each symbol the library defines of a hidden version only,
// as memcpy@GLIBC_2.2.5: no reference with no version takes it, but a
// library's own reference to that version does.
fn each_hidden_definition<F>(buf: const u8[:], t: const Tables&) {
    if t.versym_len == 0 { return; }
    let syms = buf[t.dynsym_at..t.dynsym_at + t.dynsym_len];
    let names = buf[t.dynstr_at..t.dynstr_at + t.dynstr_len];
    for i in 1..t.dynsym_len / elf::SYM_SIZE {
        let s = elf::decode_symbol(syms[i * elf::SYM_SIZE..(i + 1) * elf::SYM_SIZE]);
        let bind = elf::bind(s);
        if s.shndx as u32 == elf::SHN_UNDEF || !(bind == 1 || bind == 2 || bind == 10) { continue; }
        let version = elf::u16le(buf[t.versym_at + 2 * i..t.versym_at + 2 * i + 2], 0);
        if version & VERSYM_HIDDEN == 0 || s.name as i64 >= names.len { continue; }
        F(elf::cstr(names, s.name));
    }
}

// Calls F with each global symbol the library refers to and does not
// define, by name, and its binding (weak: 2).
fn each_reference<F>(buf: const u8[:], t: const Tables&) {
    let syms = buf[t.dynsym_at..t.dynsym_at + t.dynsym_len];
    let names = buf[t.dynstr_at..t.dynstr_at + t.dynstr_len];
    for i in 1..t.dynsym_len / elf::SYM_SIZE {
        let s = elf::decode_symbol(syms[i * elf::SYM_SIZE..(i + 1) * elf::SYM_SIZE]);
        let bind = elf::bind(s);
        if s.shndx as u32 != elf::SHN_UNDEF || !(bind == 1 || bind == 2) { continue; }
        if s.name as i64 >= names.len { continue; }
        F(elf::cstr(names, s.name), bind);
    }
}
