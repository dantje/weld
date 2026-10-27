// The rules of symbol resolution: what each occurrence of a symbol claims,
// which definition wins, which symbols leave their shard and which go in
// the output's symbol table, in what order. The shards (resolve.goose)
// apply them as occurrences arrive (shard_loop's add) and at export.
namespace resolve;
import std;

// What an occurrence of a symbol claims, weakest first, as a worker reads
// it (Entry.kind); rank orders the definitions among them.
let UNDEF_WEAK: u8 = 0;
let UNDEF: u8 = 1;
let LAZY: u8 = 2;          // an archive member would define it
let WEAK: u8 = 3;
let COMMON: u8 = 4;
let COMDAT: u8 = 5;        // defined in a section group: duplicates expected
let DEF: u8 = 6;
let PROVIDED: u8 = 7;      // by the linker, unless an input defines it
let START: u8 = 8;         // __start_X: by the linker, for the section of the definition
let STOP: u8 = 9;          // __stop_X: likewise
let GROUP: u8 = 10;        // a COMDAT group's signature: the first in command-line order is kept
let SHARED: u8 = 11;       // defined by a shared library: below any object's definition
let DSO_REF: u8 = 12;      // referenced by a shared library, which an executable exports if it defines
// The libraries only a shared library needs (link::run follows DT_NEEDED)
// come after every object's symbols, and only mark a symbol already there.
let INDIRECT: u8 = 13;     // used by one: as DSO_REF
let INDIRECT_DEF: u8 = 14; // defined by one: likewise, and a given library may use it (SHLIB_DEF)
let SHLIB_DEF: u8 = 15;    // defined by a library, of a hidden version: a given library may use it

// An occurrence's sym, for a group: the index of its SHT_GROUP section, marked.
let GROUP_MARK: u32 = 0x80000000;

// What an occurrence needs besides an address, OR'd over all of them, is
// in Entry.need and Sym.need: reloc.goose's NEED_GOT, NEED_COPY and the like.

// Which definition wins between two of different kinds: the higher. Among
// equals the first in command-line order (the lower prio), but for common
// symbols the largest.
fn rank(kind: u8) -> i64 {
    if kind == DEF || kind == COMDAT { 4 } else if kind == COMMON { 3 } else if kind == WEAK { 2 }
    else if kind == SHARED { 1 } else { 0 }
}

// Where a definition comes from: the input's position on the command line
// and, in an archive, the member header's offset. Lower wins among equals.
fn prio(file: i64, offset: i64) -> u64 { (file as! u64) << 40 | offset as! u64 }
fn prio_file(p: u64) -> i64 { (p >> 40) as! i64 }
fn prio_offset(p: u64) -> i64 { (p & ((1 << 40) - 1)) as! i64 }

// A global symbol as its shard knows it: its name (in the shard's names),
// the definition winning so far (def_*), its most constraining visibility,
// what its occurrences need, and flags: referenced, strong_ref (by a
// reference that is not weak), has_lazy and lazy_prio (an archive member
// that would define it), requested (that member asked for), pending (to
// look at in the next flush), duplicate, in_dso (a shared library defines
// or uses it), occurs (an object or the linker mentions it).
// shlib_ref: a given shared library refers to the symbol, not weakly, the
// first of them in command-line order shlib_prio. def_any: some library
// defines it, if with a version a reference with none would not take.
// copied: a shared library's data an executable copies (CMD_COPY), so that
// it defines and exports it, its aliases too.
struct Sym { hash: u64, name_at: u32, name_len: u32, def_prio: u64, def_size: u64, def_value: u64,
             def_sym: u32, def_shndx: u32, def_kind: u8, def_stype: u8, def_bind: u8, def_other: u8, vis: u8, need: u8, defined: bool,
             referenced: bool, lazy_prio: u64, has_lazy: bool,
             strong_ref: bool, requested: bool, pending: bool, duplicate: bool, in_dso: bool, occurs: bool,
             shlib_ref: bool, def_any: bool, shlib_prio: u64, copied: bool }

// Whether and how a symbol goes in the output's symbol table: one the
// linker defines only if something refers to it, an undefined one (weak,
// or the link fails) as itself. A hidden one stays global with its
// visibility, as GNU ld keeps it in an executable; EMIT_LOCAL is there for
// the linkers that make it local, which lld does.
let EMIT_NONE: u8 = 0;
let EMIT_LOCAL: u8 = 1;
let EMIT_GLOBAL: u8 = 2;
// Whether a symbol leaves its shard at export: not if no object (nor the
// linker) mentions it and it is a shared library's or no one's, as most of
// the symbols of the shared libraries an executable links are, and the
// archive symbols of members not taken. Nothing would refer to it; those
// that remain keep their order.
fn exported(s: const Sym&) -> bool { s.occurs || (s.defined && s.def_kind != SHARED) || s.copied }

fn emitted(s: Sym) -> u8 {
    if !s.defined { return if s.referenced { EMIT_GLOBAL } else { EMIT_NONE }; }
    if s.def_kind == GROUP { return EMIT_NONE; }
    if s.def_kind == SHARED { return if s.referenced { EMIT_GLOBAL } else { EMIT_NONE }; }   // as undefined
    if (s.def_kind == PROVIDED || s.def_kind == START || s.def_kind == STOP) && !s.referenced { return EMIT_NONE; }
    return EMIT_GLOBAL;
}

// How much a visibility constrains: a symbol takes the most constraining
// of all its occurrences', definitions and references alike.
fn constraint(vis: u8) -> u8 { let ranks: u8[4] = [0, 3, 2, 1]; ranks[vis] }

// The order a shard numbers its symbols in, whatever order they arrived
// in: definitions in the order of their inputs, then by name (__start_X
// and __stop_X share an input and index), then undefined symbols by name.
fn before(a: const Sym&, b: const Sym&, names: const u8[:]) -> bool {
    if a.defined != b.defined { return a.defined; }
    if a.defined && a.def_prio != b.def_prio { return a.def_prio < b.def_prio; }
    if a.defined && a.def_sym != b.def_sym { return a.def_sym < b.def_sym; }
    return compare(names[a.name_at..a.name_at + a.name_len], names[b.name_at..b.name_at + b.name_len]) < 0;
}
