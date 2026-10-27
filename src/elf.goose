// ELF64 little-endian relocatable objects for x86-64: a verify-then-read
// view over the file's bytes. `check` validates every table and offset the
// accessors rely on, once; `open` then records where the tables are, and
// the accessors decode a record on demand at constant offsets. Nothing is
// copied out of the input and nothing is allocated.
namespace elf;
import std;

let ET_REL: u16 = 1;
let EM_X86_64: u16 = 62;

let SHT_NULL: u32 = 0;
let SHT_PROGBITS: u32 = 1;
let SHT_SYMTAB: u32 = 2;
let SHT_STRTAB: u32 = 3;
let SHT_RELA: u32 = 4;
let SHT_NOBITS: u32 = 8;
let SHT_REL: u32 = 9;
let SHT_GROUP: u32 = 17;
let SHT_SYMTAB_SHNDX: u32 = 18;

let SHN_UNDEF: u32 = 0;
let SHN_LORESERVE: u32 = 0xff00;
let SHN_ABS: u32 = 0xfff1;
let SHN_COMMON: u32 = 0xfff2;
let SHN_XINDEX: u32 = 0xffff;

let EHDR_SIZE = 64;
let SHDR_SIZE = 64;
let SYM_SIZE = 24;
let RELA_SIZE = 24;

struct Section { name: u32, kind: u32, flags: u64, addr: u64, offset: u64, size: u64,
                 link: u32, info: u32, align: u64, entsize: u64 }
struct Symbol { name: u32, info: u8, other: u8, shndx: u16, value: u64, size: u64 }
struct Rela { offset: u64, sym: u32, kind: u32, addend: i64 }

fn bind(s: Symbol) -> u8 { s.info >> 4 }
fn stype(s: Symbol) -> u8 { s.info & 15 }
fn visibility(s: Symbol) -> u8 { s.other & 3 }

// Where the tables of a checked object are. Every slice is a view of data.
struct Object {
    data: const u8[:],
    shdrs: const u8[:],         // nsections headers
    shstrtab: const u8[:],
    symtab: const u8[:],        // nsymbols entries; empty without a symbol table
    strtab: const u8[:],
    symtab_shndx: const u8[:],  // 4 bytes a symbol, or empty
    symtab_index: i64,          // 0 without a symbol table
    first_global: i64,
}

fn nsections(o: const Object&) -> i64 { o.shdrs.len / SHDR_SIZE }
fn nsymbols(o: const Object&) -> i64 { o.symtab.len / SYM_SIZE }

// Little-endian loads. Callers pass a record slice whose length they
// asserted, so the indexes are constant offsets and the checks fold away.
inline fn u16le(b: const u8[:], at: i64) -> u16 { b[at] | (b[at + 1] as u16 << 8) }
inline fn u32le(b: const u8[:], at: i64) -> u32 {
    b[at] | (b[at + 1] as u32 << 8) | (b[at + 2] as u32 << 16) | (b[at + 3] as u32 << 24)
}
inline fn u64le(b: const u8[:], at: i64) -> u64 { u32le(b, at) | (u32le(b, at + 4) as u64 << 32) }

inline fn decode_section(e: const u8[:]) -> Section {
    assert(e.len >= SHDR_SIZE);
    Section { name: u32le(e, 0), kind: u32le(e, 4), flags: u64le(e, 8), addr: u64le(e, 16),
              offset: u64le(e, 24), size: u64le(e, 32), link: u32le(e, 40), info: u32le(e, 44),
              align: u64le(e, 48), entsize: u64le(e, 56) }
}
inline fn decode_symbol(e: const u8[:]) -> Symbol {
    assert(e.len >= SYM_SIZE);
    Symbol { name: u32le(e, 0), info: e[4], other: e[5], shndx: u16le(e, 6),
             value: u64le(e, 8), size: u64le(e, 16) }
}
inline fn decode_rela(e: const u8[:]) -> Rela {
    assert(e.len >= RELA_SIZE);
    let info = u64le(e, 8);
    Rela { offset: u64le(e, 0), sym: (info >> 32) as! u32, kind: info as! u32, addend: u64le(e, 16) as! i64 }
}

fn section(o: const Object&, i: i64) -> Section { decode_section(o.shdrs[i * SHDR_SIZE..i * SHDR_SIZE + SHDR_SIZE]) }
fn symbol(o: const Object&, i: i64) -> Symbol { decode_symbol(o.symtab[i * SYM_SIZE..i * SYM_SIZE + SYM_SIZE]) }

// The NUL-terminated string at off; check verified that every string table
// ends in a NUL and that every name offset is inside its table.
let NUL = byte_set([0 as u8]);
fn cstr(table: const u8[:], off: u32) -> const u8[:] {
    let rest = table[off..];
    return rest[..find_any(rest, NUL)];
}
fn section_name(o: const Object&, s: Section) -> const u8[:] { cstr(o.shstrtab, s.name) }
fn symbol_name(o: const Object&, s: Symbol) -> const u8[:] { cstr(o.strtab, s.name) }

// A section's bytes; empty for SHT_NOBITS.
fn contents(o: const Object&, s: Section) -> const u8[:] {
    if s.kind == SHT_NOBITS { return o.data[..0]; }
    let at = s.offset as! i64;
    return o.data[at..at + s.size as! i64];
}

// The section a symbol is defined in, or one of the SHN_ values, with
// SHN_XINDEX resolved through SHT_SYMTAB_SHNDX.
fn symbol_section(o: const Object&, i: i64, s: Symbol) -> u32 {
    if s.shndx != SHN_XINDEX { return s.shndx; }
    return u32le(o.symtab_shndx[i * 4..i * 4 + 4], 0);
}

fn nrelas(s: Section) -> i64 { (s.size / RELA_SIZE) as! i64 }
fn rela(o: const Object&, s: Section, i: i64) -> Rela {
    let at = s.offset as! i64 + i * RELA_SIZE;
    decode_rela(o.data[at..at + RELA_SIZE])
}

// The section count and the section-name table's index, with ELF's
// extended numbering: past 0xff00 sections both live in section 0.
fn counts(data: const u8[:]) -> i64, i64, i64 {
    let shoff = u64le(data, 40) as! i64;
    var shnum = u16le(data, 60) as i64;
    var shstrndx = u16le(data, 62) as i64;
    if shoff != 0 && (shnum == 0 || shstrndx == SHN_XINDEX) {
        let s0 = decode_section(data[shoff..shoff + SHDR_SIZE]);
        if shnum == 0 { shnum = s0.size as! i64; }
        if shstrndx == SHN_XINDEX { shstrndx = s0.link; }
    }
    return shoff, shnum, shstrndx;
}

// Whether [off, off + size) lies within len, without overflow.
fn in_range(off: u64, size: u64, len: i64) -> bool { off <= len as u64 && size <= len as u64 - off }

fn ends_in_nul(table: const u8[:]) -> bool { table.len > 0 && table[table.len - 1] == 0 }

fn headers_only(data: const u8[:], shoff: i64, shnum: i64) -> Object {
    let none = data[..0];
    Object { data: data, shdrs: data[shoff..shoff + shnum * SHDR_SIZE], shstrtab: none, symtab: none,
             strtab: none, symtab_shndx: none, symtab_index: 0, first_global: 0 }
}

// Empty if data is an object every accessor can read; else what is wrong.
fn check(data: const u8[:]) -> u8[>..] {
    guard data.len >= EHDR_SIZE else { return str("file too short for an ELF header"); }
    guard data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F' else { return str("not an ELF file"); }
    guard data[4] == 2 && data[5] == 1 else { return str("not ELF64 little-endian"); }
    guard u16le(data, 16) == ET_REL else { return str("not a relocatable object (e_type ", u16le(data, 16), ")"); }
    guard u16le(data, 18) == EM_X86_64 else { return str("not x86-64 (e_machine ", u16le(data, 18), ")"); }
    let shoff = u64le(data, 40);
    guard shoff == 0 || u16le(data, 58) as i64 == SHDR_SIZE else { return str("unexpected e_shentsize"); }
    guard in_range(shoff, SHDR_SIZE, data.len) else { return str("section headers past end of file"); }
    let _, shnum, shstrndx = counts(data);
    guard in_range(shoff, (shnum as! u64) * SHDR_SIZE, data.len) && shnum < 1 << 32 else {
        return str("section headers past end of file");
    }
    guard shnum == 0 || shstrndx < shnum else { return str("e_shstrndx out of range"); }

    // Every section's place, and the links open follows, before it follows them.
    let hdrs = headers_only(data, shoff as! i64, shnum);
    var nsymtabs = 0;
    for i in 1..shnum {
        let s = section(hdrs, i);
        guard s.kind == SHT_NOBITS || in_range(s.offset, s.size, data.len) else {
            return str("section ", i, " past end of file");
        }
        guard s.align == 0 || (s.align & (s.align - 1)) == 0 else { return str("section ", i, ": alignment not a power of two"); }
        if s.kind == SHT_SYMTAB {
            nsymtabs++;
            guard s.entsize == SYM_SIZE && s.size % SYM_SIZE == 0 else { return str("bad symbol table size"); }
            guard s.link > 0 && (s.link) < shnum && section(hdrs, s.link).kind == SHT_STRTAB else {
                return str("symbol table's string table is not one");
            }
            guard s.info <= s.size / SYM_SIZE else { return str("symbol table's sh_info out of range"); }
        }
    }
    guard nsymtabs <= 1 else { return str("more than one symbol table"); }
    guard shnum == 0 || section(hdrs, shstrndx).kind == SHT_STRTAB else { return str("bad section-name table"); }

    let o = open_unchecked(data);
    guard shnum == 0 || ends_in_nul(o.shstrtab) else { return str("section-name table does not end in a NUL"); }
    guard o.symtab.len == 0 || ends_in_nul(o.strtab) else { return str("symbol string table does not end in a NUL"); }

    let nsym = nsymbols(o);
    for i in shnum {                     // section 0 too: its name is readable
        let s = section(o, i);
        guard s.name < o.shstrtab.len as! u32 else { return str("section ", i, ": name out of range"); }
        if i == 0 { continue; }              // the rest of section 0 is extended numbering
        if s.kind == SHT_REL { return str("section ", i, ": SHT_REL relocations are not used on x86-64"); }
        if s.kind == SHT_RELA {
            guard s.entsize == RELA_SIZE && s.size % RELA_SIZE == 0 else { return str("section ", i, ": bad relocation table size"); }
            guard s.link == o.symtab_index && o.symtab_index > 0 else { return str("section ", i, ": relocations not against the symbol table"); }
            guard s.info > 0 && (s.info) < shnum else { return str("section ", i, ": relocated section out of range"); }
        }
        if s.kind == SHT_SYMTAB_SHNDX {
            guard s.link == o.symtab_index && s.size == (nsym * 4) as! u64 else { return str("bad SHT_SYMTAB_SHNDX"); }
        }
        if s.kind == SHT_GROUP {
            guard s.size >= 4 && s.size % 4 == 0 && s.link == o.symtab_index && o.symtab_index > 0 else {
                return str("section ", i, ": bad group");
            }
            guard (s.info) < nsym else { return str("section ", i, ": group signature out of range"); }
            let words = contents(o, s);
            for k in 1..words.len / 4 {
                let member = u32le(words[k * 4..k * 4 + 4], 0) as i64;
                guard member > 0 && member < shnum else { return str("section ", i, ": group member out of range"); }
            }
        }
    }
    guard o.symtab_shndx.len == 0 || o.symtab_shndx.len == nsym * 4 else { return str("bad SHT_SYMTAB_SHNDX"); }

    // Every symbol's name and section, the null symbol's included.
    for i in nsym {
        let s = symbol(o, i);
        guard s.name < o.strtab.len as! u32 else { return str("symbol ", i, ": name out of range"); }
        let shndx = s.shndx as u32;
        if shndx == SHN_XINDEX {
            guard o.symtab_shndx.len > 0 else { return str("symbol ", i, ": SHN_XINDEX without SHT_SYMTAB_SHNDX"); }
            guard (symbol_section(o, i, s)) < shnum else { return str("symbol ", i, ": section out of range"); }
        } else if shndx >= SHN_LORESERVE {
            guard shndx == SHN_ABS || shndx == SHN_COMMON else { return str("symbol ", i, ": unknown special section ", shndx); }
        } else {
            guard (shndx) < shnum else { return str("symbol ", i, ": section out of range"); }
        }
    }
    return [];
}

// The tables of an object whose section headers check accepted.
fn open_unchecked(data: const u8[:]) -> Object {
    let shoff, shnum, shstrndx = counts(data);
    var o = headers_only(data, shoff, shnum);
    for i in 1..shnum {
        let s = section(o, i);
        if s.kind == SHT_SYMTAB {
            o.symtab = contents(o, s);
            o.symtab_index = i;
            o.first_global = s.info;
            o.strtab = contents(o, section(o, s.link));
        } else if s.kind == SHT_SYMTAB_SHNDX {
            o.symtab_shndx = contents(o, s);
        }
    }
    if shnum > 0 { o.shstrtab = contents(o, section(o, shstrndx)); }
    return o;
}

// The object in data, or why it is not one.
fn open(data: const u8[:]) -> Object, u8[>..] {
    let err = check(data);
    if err.len > 0 { return headers_only(data, 0, 0), err; }
    return open_unchecked(data), err;
}
