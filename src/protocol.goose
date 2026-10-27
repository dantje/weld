// What main and the workers send each other (docs/design.md has the
// table of every message, the shards' included). Main queues a Job; the
// worker that takes it answers with a JobDone, preceded by an ObjInfo for
// each object it read (the sections main lays out, as Secs), a DsoInfo for
// a shared library, and for a relocation job asked for them its Fdes.
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

// The kinds of Job, and what each reads of it besides fd, path and shards.
let JOB_OBJECT: u8 = 0;    // read the object of size bytes at offset, file's input
let JOB_INDEX: u8 = 1;     // an archive's symbol index, size bytes at offset, words aux bytes wide
let JOB_MEMBER: u8 = 2;    // the archive members whose headers are at the offsets in data
let JOB_RELOCATE: u8 = 3;  // relocate and write the object at offset: at, and its tables in data (RelocAt)
let JOB_STOP: u8 = 4;      // the worker ends

let JOB_POPULATE: u8 = 5;  // fault in size bytes of the output at offset, for writing (ld_populate)
let JOB_SHARED: u8 = 6;    // a shared library, size bytes: what it defines
// A job. file is the input's number (prios count from it); aux is an
// index's word width (JOB_INDEX) or an indirect library's number among
// them (JOB_SHARED).
// hide: an archive's members' definitions are hidden (--exclude-libs).
// indirect: a shared library only another needs, not given (follow_needed).
// refs: a shared library's references are sent too, and what it needs is
// reported, for a PIE's exports or Options.shlib_check.
// For a relocation job: out is the output; hash_id, what it writes goes
// into a build-ID sum; fdes, it sends its FDEs; shared, the output has
// dynamic tables (a shared library, or a PIE: pie); at, RelocAt.
struct Job { kind: u8, fd: i32, out: i32, shards: i32, file: i64, offset: i64, size: i64, aux: i64, fdes: bool,
             shared: bool, pie: bool, refs: bool, hide: bool, indirect: bool, hash_id: bool, at: RelocAt,
             path: u8[..200], data: u64[>..] }

// What a relocation job needs of the output besides its own tables, and
// how those tables are laid out in Job.data. The tables, in order: each
// section's place (layout's address, its output section's index in the
// top 16 bits, or reloc::NOT_PLACED); each global symbol's address
// (imports); its GOT slot and PLT entry numbers (slots, from 1, in 32 bits
// each); with dynamic tables, its dynamic symbol and TLS pair (dynx); the
// output sections' deltas, ndeltas of them (an output section's file
// offset minus its address); its merged strings' addresses, npieces.
// symtab_at: where its local symbols go; strtab_at and str_index: .strtab's
// offset and the number of the bytes before its names; tp: the thread
// pointer's offset from the TLS image's end; tls_start: the TLS image's
// address; got, plt: their addresses; rela_at and rela_room: where its
// run-time relocations go and how many fit; tlsld_got: the local-dynamic
// TLS pair's GOT slot.
struct RelocAt { symtab_at: u64, strtab_at: u64, str_index: u64, tp: u64, tls_start: u64, got: u64, plt: u64,
                 rela_at: u64, rela_room: u64, tlsld_got: u64, ndeltas: i64, npieces: i64 }

// A relocation job's FDEs, when it was asked for them: the address of the
// code each describes and its own, in pairs.
struct Fdes { pairs: u64[>..] }

// objects and dsos count the descriptions of objects and shared libraries
// the job sends main after it.
// ida and idb: a relocation job's build-ID sum (xxh3::IdSum).
struct JobDone { errors: i64, objects: i64, dsos: i64, ida: u64, idb: u64 }

// A shared library's name, as DT_NEEDED gives it, and in text: its
// versions, ver_len bytes, for each its index in two bytes and its name,
// ended with a 0; then the libraries it needs, needed_len bytes, each
// ended with a 0; then its DT_RUNPATH (or DT_RPATH). An indirect one's prio
// is its number among them.
struct DsoInfo { prio: u64, indirect: bool, soname: u8[..256], ver_len: i64, needed_len: i64, text: u8[>..] }

// An object as main needs it for layout: its sections by index, as main
// keeps them, so that it appends them at once. abs_locals and abs_strs
// count the local symbols defined in no section that go in the output's
// symbol table, file symbols among them. features and isa are what the
// object's .note.gnu.property says: x86 features all its code has (0 if
// it has no note), and the x86 ISA levels it needs.
// tlsld says whether it accesses TLS of its own local-dynamically. abs64,
// locals, local_strs and fdes total its sections' R_X86_64_64 relocations
// (which become run-time relocations in a shared library), local symbols
// in the output's symbol table and their names' bytes, and FDEs; its
// COMDAT groups' totals among them, which leave with a group that loses.
// merge_mask has a bit for each shard the worker sent strings to merge,
// and pieces counts those strings, numbered through the object;
// merge_bytes is the most they take merged, at their alignment. eh is the
// index of its .eh_frame section if it has one whose FDEs can be left out
// with the code they describe (Sec's eh_bytes), else -1.
struct ObjInfo { prio: u64, offset: i64, size: i64, first_global: i64, nsyms: i64, abs_locals: i64, abs_strs: i64,
                 features: u32, isa: u32, tlsld: bool, merge_mask: u32, pieces: i64, merge_bytes: i64, eh: i64, abs64: i64,
                 locals: i64, local_strs: i64, fdes: i64, secs: Sec[>..] }

fn label(path: const u8[:]) -> const u8[:] { path[..min(path.len, 200)] }

fn job(kind: u8, fd: i32, shards: i64, file: i64, offset: i64, size: i64, aux: i64, path: const u8[:]) -> Job {
    Job { kind: kind, fd: fd, out: -1, shards: shards as! i32, file: file, offset: offset, size: size, aux: aux,
          fdes: false, shared: false, pie: false, refs: false, hide: false, indirect: false, hash_id: false,
          at: RelocAt { symtab_at: 0, strtab_at: 0, str_index: 0, tp: 0, tls_start: 0, got: 0, plt: 0, rela_at: 0,
                        rela_room: 0, tlsld_got: 0, ndeltas: 0, npieces: 0 },
          path: label(path), data: [] }
}

// A section, as a worker describes it and main lays it out: 32 bytes, as
// main's passes over every section take longer for each byte more; what
// only counts in sums is summed by object (ObjInfo). Within an output
// section, sections go in order of key, then in command-line order: key is
// an .init_array section's priority, or the hash of a name __start_ and
// __stop_ symbols can name, keeping sections of that name together after
// the rest. align2 is its alignment's log2, group the index of the
// SHT_GROUP section it belongs to, or 0. addr is main's to fill in.
// An SHT_GROUP section's own record holds its members' totals instead,
// which leave its object's if the group loses (group_totals).
struct Sec { class: u8, named: bool, align2: u8, group: u32, key: u64, size: u64, addr: u64 }

fn sec_align(s: const Sec&) -> u64 { (1 as u64) << s.align2 }

fn log2(x: u64) -> u8 {
    var n: u8 = 0;
    while (1 as u64) << n < x { n++; }
    return n;
}

// A group's members' totals, in its SHT_GROUP section's record: key their
// R_X86_64_64 relocations (low half) and FDEs, those in .eh_frame and of
// code in it (high half), size their local symbols in the output's symbol
// table (low) and those names' bytes (high), addr the bytes of the FDEs of
// their code.
struct Totals { abs64: u64, fdes: u64, locals: u64, local_strs: u64, eh_bytes: u64 }

fn group_totals(g: const Sec&) -> Totals {
    Totals { abs64: g.key & 0xffffffff, fdes: g.key >> 32, locals: g.size & 0xffffffff, local_strs: g.size >> 32,
             eh_bytes: g.addr }
}

fn add_to_group(g: Sec&, abs64: u64, fdes: u64, locals: u64, local_strs: u64, eh_bytes: u64) {
    g.key += abs64 + (fdes << 32);
    g.size += locals + (local_strs << 32);
    g.addr += eh_bytes;
}
