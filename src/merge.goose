// Merging strings: the sections of strings (SHF_MERGE and SHF_STRINGS)
// every object has, .debug_str, .debug_line_str, .comment and the
// .rodata.str* of string literals, become one copy of each string; and the
// sections of constants (SHF_MERGE alone, .rodata.cst*), entsize bytes
// each, one copy of each constant. Constants are strings of a fixed size
// here, in groups of their own.
//
// A worker describing an object splits each such section into its strings,
// each with its terminator, and sends each string to the shard its hash
// picks; main learns only how many strings each section has. Each shard
// keeps one copy of each, in the order of its first use (command-line,
// then section, then string order), and tells main how large its part of
// each merge group is and where each string went. A merge group is what
// shares one output: the output section, the strings' width and their
// alignment. Main lays out each group as one section, and the worker
// relocating an object takes its strings' addresses with the job:
// references into a merged section, through its section symbol plus an
// addend or through a local label, go to the string's copy, as lld maps
// them. The shards write the strings.
namespace merge;
import std;
import .elf;
import .layout;

let SHF_MERGE: u64 = 0x10;
let SHF_STRINGS: u64 = 0x20;

fn log2(x: u64) -> u32 {
    var n: u32 = 0;
    while (1 as u64) << n < x { n++; }
    return n;
}

// A merge group, packed: the output section's class and keep key, the
// width of a character (of a constant) and the alignment, as powers of
// two, and whether it holds constants.
fn group(class: u8, key: u64, entsize: u64, align: u64, constants: bool) -> u32 {
    class | (key as! u32) << 8 | log2(entsize) << 16 | log2(align) << 20 | (if constants { 1 << 26 } else { 0 })
}
fn constants_of(g: u32) -> bool { g & (1 << 26) != 0 }
fn class_of(g: u32) -> u8 { (g & 0xff) as! u8 }
fn key_of(g: u32) -> u64 { (g >> 8) & 0xff }
fn entsize_of(g: u32) -> i64 { 1 << ((g >> 16) & 0xf) }
fn align_of(g: u32) -> u64 { (1 as u64) << ((g >> 20) & 0x3f) }

// The merge group of section s of class class (key its keep key), or 0 if
// it is not merged: strings 1, 2 or 4 bytes a character, or constants of a
// power of two bytes to 64, read-only, kept, in no COMDAT group (grouped),
// with no relocations of its own (relocated) and no global symbol defined
// in it (global); strings must all end, and constants fill it.
fn group_of(s: elf::Section, class: u8, key: u64, grouped: bool, relocated: bool, global: bool) -> u32 {
    if s.flags & SHF_MERGE == 0 || s.flags & layout::SHF_WRITE != 0 { return 0; }
    let constants = s.flags & SHF_STRINGS == 0;
    if constants {
        if s.entsize == 0 || s.entsize > 64 || s.entsize & (s.entsize - 1) != 0 || s.size % s.entsize != 0 { return 0; }
    } else if s.entsize != 1 && s.entsize != 2 && s.entsize != 4 {
        return 0;
    }
    if class == layout::DISCARD || (class == layout::NONALLOC && key == 0) || key > 0xff { return 0; }
    if s.kind != 1 || grouped || relocated || global || s.size == 0 { return 0; }
    let align = max(1, s.align);
    if align & (align - 1) != 0 || align > (1 as u64) << 12 { return 0; }
    return group(class, key, s.entsize, align, constants);
}

// Appends the start of each string in b, entsize bytes a character, to
// starts; of each constant, entsize bytes apiece, for a group of them (g).
// False if the last string has no terminator: then nothing is appended,
// and the section is not merged.
fn split(b: const u8[:], g: u32, starts: u64[>..]&) -> bool {
    let entsize = entsize_of(g);
    if constants_of(g) {
        guard b.len % entsize == 0 else { return false; }
        for k in b.len / entsize { starts.push((k * entsize) as! u64); }
        return true;
    }
    let first = starts.len;
    var at = 0;
    var i = 0;
    if entsize == 1 {
        let zero = byte_set("\x00");
        while i < b.len {
            let z = find_any(b[i..], zero);
            if z < 0 { break; }
            starts.push(at as! u64);
            i += z + 1;
            at = i;
        }
    } else {
        while i + entsize <= b.len {
            var zero = true;
            for k in entsize { if b[i + k] != 0 { zero = false; } }
            i += entsize;
            if zero { starts.push(at as! u64); at = i; }
        }
        if i != b.len { at = -1; }
    }
    if at != b.len { starts.resize(first, 0); return false; }
    return true;
}

// Which of an object's sections are relocated (a SHT_RELA names them) and
// which define global symbols, for group_of.
fn section_facts(o: const elf::Object&, relocated: bool[>..]&, global: bool[>..]&) {
    let ns = elf::nsections(o);
    relocated.resize(ns, false);
    global.resize(ns, false);
    for i in 1..ns {
        let s = elf::section(o, i);
        if s.kind == elf::SHT_RELA && s.info < ns as! u32 { relocated[s.info] = true; }
    }
    for i in o.first_global..elf::nsymbols(o) {
        let s = elf::symbol(o, i);
        let k = elf::symbol_section(o, i, s);
        if k > 0 && k < ns { global[k] = true; }
    }
}

// The index of the string in starts[lo..hi] that offset falls in, or -1
// if before the first.
fn piece(starts: const u64[:], lo: i64, hi: i64, offset: u64) -> i64 {
    if hi <= lo || offset < starts[lo] { return -1; }
    var a = lo;
    var b = hi;
    while b - a > 1 {
        let m = (a + b) / 2;
        if starts[m] <= offset { a = m; } else { b = m; }
    }
    return a;
}
