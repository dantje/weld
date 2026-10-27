// Applying x86-64 relocations to one section's bytes, in a worker.
//
// A relocation job carries, for an object, an address and a file offset
// for each of its sections (NOT_PLACED for one left out, or for bytes not
// in the file), then for each of its global symbols from the first global
// on its address, then its GOT slot's address (0 if it has none). tp is
// the thread pointer's address relative to the TLS image, so that a TLS
// symbol's offset from it is its address less tp.
namespace reloc;
import std;
import .elf;

let NOT_PLACED: u64 = 0xffffffffffffffff;

let R_X86_64_NONE: u32 = 0;
let R_X86_64_64: u32 = 1;
let R_X86_64_PC32: u32 = 2;
let R_X86_64_PLT32: u32 = 4;
let R_X86_64_GOTPCREL: u32 = 9;
let R_X86_64_32: u32 = 10;
let R_X86_64_32S: u32 = 11;
let R_X86_64_16: u32 = 12;
let R_X86_64_PC16: u32 = 13;
let R_X86_64_8: u32 = 14;
let R_X86_64_PC8: u32 = 15;
let R_X86_64_DTPOFF64: u32 = 17;
let R_X86_64_TPOFF64: u32 = 18;
let R_X86_64_TLSGD: u32 = 19;
let R_X86_64_TLSLD: u32 = 20;
let R_X86_64_DTPOFF32: u32 = 21;
let R_X86_64_GOTTPOFF: u32 = 22;
let R_X86_64_TPOFF32: u32 = 23;
let R_X86_64_PC64: u32 = 24;
let R_X86_64_GOTPCRELX: u32 = 41;
let R_X86_64_REX_GOTPCRELX: u32 = 42;

// What the relocations of a symbol need of it, OR'd over all of them, as
// read before it is known whether the symbol is preemptible (defined by
// whatever is loaded first, in a shared library) or the output shared:
let NEED_GOT: u8 = 1;            // a GOT slot holding its address
let NEED_TLS_GOT: u8 = 2;        // a GOT slot holding its offset from the thread pointer
let NEED_GOT_RELAXABLE: u8 = 4;  // a GOT slot, if it is preemptible; else its instruction does without
let NEED_PLT: u8 = 8;            // a PLT entry, if it is preemptible: it is called
let NEED_IE_RELAXABLE: u8 = 16;  // NEED_TLS_GOT, in a shared library; an executable does without
let NEED_TLSGD: u8 = 32;         // a module and offset pair, in a shared library
// A direct reference (PC32): to a shared library's data, from an executable,
// it is to a copy of it the executable makes (a copy relocation), as gcc's
// position-independent code expects; clang's goes through the GOT.
let NEED_COPY: u8 = 64;

fn may_need_got(kind: u32) -> bool {
    kind == R_X86_64_GOTPCREL || kind == R_X86_64_GOTPCRELX || kind == R_X86_64_REX_GOTPCRELX ||
        kind == R_X86_64_GOTTPOFF || kind == R_X86_64_PLT32 || kind == R_X86_64_PC32 || kind == R_X86_64_TLSGD
}

// What a relocation of this type at offset at in b needs of its symbol.
fn got_need(kind: u32, b: const u8[:], at: i64) -> u8 {
    if kind == R_X86_64_GOTPCREL { return NEED_GOT; }
    if kind == R_X86_64_GOTPCRELX || kind == R_X86_64_REX_GOTPCRELX {
        return if gotpcrelx_relaxable(kind, b, at) { NEED_GOT_RELAXABLE } else { NEED_GOT };
    }
    if kind == R_X86_64_GOTTPOFF { return if ie_relaxable(b, at) { NEED_IE_RELAXABLE } else { NEED_TLS_GOT }; }
    if kind == R_X86_64_PLT32 { return NEED_PLT; }
    if kind == R_X86_64_PC32 { return NEED_PLT | NEED_COPY; }
    if kind == R_X86_64_TLSGD { return NEED_TLSGD; }
    return 0;
}

// Whether mov, call or jmp through foo@GOTPCREL(%rip) can go to foo directly.
fn gotpcrelx_relaxable(kind: u32, b: const u8[:], at: i64) -> bool {
    if at >= 2 && at + 4 <= b.len && b[at - 2] == 0x8b { return true; }                       // mov
    return kind == R_X86_64_GOTPCRELX && at >= 2 && at + 4 <= b.len && b[at - 2] == 0xff &&
           (b[at - 1] == 0x15 || b[at - 1] == 0x25);                                          // call, jmp
}

// Whether an initial-exec access, mov or add of foo@gottpoff(%rip) to a
// 64-bit register, can take the offset as an immediate instead.
fn ie_relaxable(b: const u8[:], at: i64) -> bool {
    at >= 3 && at + 4 <= b.len && (b[at - 3] & 0xf8) == 0x48 && (b[at - 2] == 0x8b || b[at - 2] == 0x03) &&
        (b[at - 1] & 0xc7) == 0x05
}

fn put(b: u8[>..]&, at: i64, v: u64, n: i64) { for k in n { b[at + k] = (v >> (8 * k)) as! u8; } }

fn fits_signed(v: u64, bits: i64) -> bool {
    let x = v as! i64;
    x >= -(1 << (bits - 1)) && x < 1 << (bits - 1)
}
fn fits_unsigned(v: u64, bits: i64) -> bool { v >> bits == 0 }

fn matches(b: const u8[:], at: i64, bytes: const u8[:]) -> bool {
    at >= 0 && at + bytes.len <= b.len && b[at..at + bytes.len] == bytes
}

// The address of symbol i, or NOT_PLACED if its section was left out.
fn symbol_address(o: const elf::Object&, i: i64, place: const u64[:], imports: const u64[:]) -> u64 {
    if i >= o.first_global { return imports[i - o.first_global]; }
    let s = elf::symbol(o, i);
    let shndx = elf::symbol_section(o, i, s);
    if shndx == elf::SHN_ABS { return s.value; }
    if shndx == elf::SHN_UNDEF || shndx >= elf::SHN_LORESERVE { return 0; }
    let base = place[2 * shndx];
    if base == NOT_PLACED { return NOT_PLACED; }
    return base + s.value;
}

// Applies relocations from to to (exclusive) in table rela to b, the bytes
// of the section at address addr. Empty if they all applied; else what
// went wrong.
// What relocating needs besides an object's own: the thread pointer's
// address relative to the TLS image (tp) and where that image starts; for
// a shared library, the local-dynamic module's GOT pair, and whether the
// section is writable, as one with run-time relocations must be.
// A section not loaded (alloc false), debugging information, takes plain
// values, and tombstone for references into sections left out.
// dynamic says the output is position-independent, with a dynamic linker
// to relocate it: a shared library (shared) or a PIE executable, whose
// TLS is its own and found as in a static one.
struct Context { tp: u64, tls_start: u64, shared: bool, dynamic: bool, tlsld_got: u64, writable: bool, alloc: bool,
                 tombstone: u64 }

// For a shared library, a global symbol's dynamic symbol index and whether
// it is preemptible, packed: PREEMPTIBLE set, the index below.
let PREEMPTIBLE: u64 = 0x8000000000000000;

// Run-time relocations go to dyn, an Elf64_Rela each (dynamic::rela).
fn dyn_rela(dyn: u8[>..]&, offset: u64, kind: u64, sym: u64, addend: u64) {
    for v in [offset, sym << 32 | kind, addend] { for k in 8 { dyn.push((v >> (8 * k)) as! u8); } }
}

// A local symbol in a section whose strings were merged (merge.goose)
// stands for one of them: the one at its value, plus the addend for a
// section symbol, which the addend then is spent on. msec gives each local
// symbol's section if it is such a one, else 0 (empty if the object has
// none); mrange each section's strings, two a section, the first and the
// end in mstart, their offsets in the section, and maddr, their addresses.
fn apply(o: const elf::Object&, rela: elf::Section, from: i64, to: i64, b: u8[>..]&, addr: u64, place: const u64[:],
         imports: const u64[:],
         gots: const u64[:], plts: const u64[:], dyns: const u64[:], tlsgds: const u64[:], ctx: const Context&,
         dyn: u8[>..]&, msec: const u32[:], mrange: const i64[:], mstart: const u64[:], maddr: const u64[:]) -> u8[>..] {
    let tp = ctx.tp;
    var skip = false;          // the call that a relaxed TLS sequence replaced
    var hint = 0;              // the merged string last referred to
    for k in from..to {
        if skip { skip = false; continue; }
        let r = elf::rela(o, rela, k);
        guard r.sym < elf::nsymbols(o) else { return str("relocation ", k, ": symbol ", r.sym, " out of range"); }
        let width = if r.kind == R_X86_64_64 || r.kind == R_X86_64_PC64 || r.kind == R_X86_64_TPOFF64 ||
                       r.kind == R_X86_64_DTPOFF64 { 8 }
                    else if r.kind == R_X86_64_16 || r.kind == R_X86_64_PC16 { 2 }
                    else if r.kind == R_X86_64_8 || r.kind == R_X86_64_PC8 { 1 }
                    else if r.kind == R_X86_64_NONE { 0 } else { 4 };
        guard r.offset <= b.len as u64 && width as u64 <= b.len as u64 - r.offset else {
            return str("relocation ", k, ": offset ", r.offset, " past the section's end");
        }
        let at = r.offset as! i64;
        // A section left out is a duplicate COMDAT copy; what refers to it,
        // such as the .eh_frame entry of a function copy, gets 0.
        var found = symbol_address(o, r.sym, place, imports);
        var a = r.addend as! u64;
        if r.sym < msec.len && msec[r.sym] != 0 {
            let y = elf::symbol(o, r.sym);
            let m = msec[r.sym] as! i64;
            let section = elf::stype(y) == 3;
            let offset = y.value + (if section { a } else { 0 });
            let first = mrange[2 * m];
            let end = mrange[2 * m + 1];
            // References mostly come in the strings' order: the last one
            // found or the next, else a search.
            if hint < first || hint >= end { hint = first; }
            if offset >= mstart[hint] && hint + 1 < end && offset >= mstart[hint + 1] { hint++; }
            if offset < mstart[hint] || (hint + 1 < end && offset >= mstart[hint + 1]) {
                var lo = first;
                var hi = end;
                while hi - lo > 1 {
                    let mid = (lo + hi) / 2;
                    if mstart[mid] <= offset { lo = mid; } else { hi = mid; }
                }
                hint = lo;
            }
            guard offset >= mstart[hint] && (hint + 1 < end || offset < elf::section(o, m).size) else {
                return str("relocation ", k, ": offset ", offset, " past the end of merged strings");
            }
            found = maddr[hint] + (offset - mstart[hint]);
            if section { a = 0; }
        }
        let s = if found == NOT_PLACED { ctx.tombstone } else { found };
        let p = addr + r.offset;
        let global = r.sym >= o.first_global;
        let g = if global { r.sym - o.first_global } else { 0 };
        let got = if global { gots[g] } else { 0 };
        let pre = ctx.dynamic && ctx.alloc && global && dyns[g] & PREEMPTIBLE != 0;
        // An executable reaches a shared library's TLS through the GOT
        // (initial-exec, as compilers make it); other models it does not.
        if pre && !ctx.shared && is_tls(r.kind) && r.kind != R_X86_64_GOTTPOFF {
            return str("relocation ", k, ": a shared library's TLS from an executable, other than initial-exec");
        }
        if r.kind == R_X86_64_NONE {
        } else if found == NOT_PLACED && !ctx.alloc && (r.kind == R_X86_64_64 || r.kind == R_X86_64_32) {
            put(b, at, ctx.tombstone, width);          // the tombstone itself, without the addend
        } else if r.kind == R_X86_64_64 && ctx.dynamic && ctx.alloc {
            // Where the output is loaded is known at run time: relative to
            // that, or bound to the symbol the dynamic linker finds.
            guard ctx.writable else { return str("relocation ", k, ": R_X86_64_64 in a read-only section; recompile with -fPIC"); }
            if pre {
                put(b, at, 0, 8);
                dyn_rela(dyn, p, 1, dyns[g] & 0xffffffff, a);
            } else if found != NOT_PLACED {
                put(b, at, s + a, 8);
                dyn_rela(dyn, p, 8, 0, s + a);
            }
        } else if r.kind == R_X86_64_64 {
            put(b, at, s + a, 8);
        } else if r.kind == R_X86_64_PC64 {
            put(b, at, s + a - p, 8);
        } else if (r.kind == R_X86_64_PC32 || r.kind == R_X86_64_PLT32) && pre {
            // A call to whatever defines it at run time goes through the PLT.
            guard plts[g] != 0 else {
                return str("relocation ", k, ": R_X86_64_PC32 against a preemptible symbol; recompile with -fPIC");
            }
            let v = plts[g] + a - p;
            guard fits_signed(v, 32) else { return str("relocation ", k, ": PLT32 out of range"); }
            put(b, at, v, 4);
        } else if r.kind == R_X86_64_PC32 || r.kind == R_X86_64_PLT32 {
            let v = s + a - p;
            guard fits_signed(v, 32) else { return str("relocation ", k, ": PC32 out of range"); }
            put(b, at, v, 4);
        } else if (r.kind == R_X86_64_32 || r.kind == R_X86_64_32S) && ctx.dynamic && ctx.alloc {
            return str("relocation ", k, ": absolute 32-bit relocation in position-independent output; recompile with -fPIC");
        } else if r.kind == R_X86_64_32 {
            guard fits_unsigned(s + a, 32) else { return str("relocation ", k, ": R_X86_64_32 out of range"); }
            put(b, at, s + a, 4);
        } else if r.kind == R_X86_64_32S {
            guard fits_signed(s + a, 32) else { return str("relocation ", k, ": R_X86_64_32S out of range"); }
            put(b, at, s + a, 4);
        } else if r.kind == R_X86_64_16 || r.kind == R_X86_64_PC16 || r.kind == R_X86_64_8 || r.kind == R_X86_64_PC8 {
            let v = if r.kind == R_X86_64_16 || r.kind == R_X86_64_8 { s + a } else { s + a - p };
            guard fits_signed(v, width * 8) || fits_unsigned(v, width * 8) else { return str("relocation ", k, " out of range"); }
            put(b, at, v, width);
        } else if r.kind == R_X86_64_GOTPCREL || r.kind == R_X86_64_GOTPCRELX || r.kind == R_X86_64_REX_GOTPCRELX {
            let need = if got_need(r.kind, b, at) == NEED_GOT_RELAXABLE && !pre { 0 } else { NEED_GOT };
            if need == 0 && b[at - 2] == 0x8b {
                b[at - 2] = 0x8d;                     // mov foo@GOTPCREL(%rip) becomes lea foo(%rip)
                let v = s + a - p;
                guard fits_signed(v, 32) else { return str("relocation ", k, ": GOTPCRELX out of range"); }
                put(b, at, v, 4);
            } else if need == 0 && b[at - 1] == 0x15 {
                b[at - 2] = 0x67;                     // call *foo@GOTPCREL(%rip) becomes addr32 call foo
                b[at - 1] = 0xe8;
                let v = s + a - p;
                guard fits_signed(v, 32) else { return str("relocation ", k, ": GOTPCRELX out of range"); }
                put(b, at, v, 4);
            } else if need == 0 {
                b[at - 2] = 0xe9;                     // jmp *foo@GOTPCREL(%rip) becomes jmp foo; nop
                let v = s + a - p + 1;
                guard fits_signed(v, 32) else { return str("relocation ", k, ": GOTPCRELX out of range"); }
                put(b, at - 1, v, 4);
                b[at + 3] = 0x90;
            } else {
                guard got != 0 else { return str("relocation ", k, ": no GOT slot for symbol ", r.sym); }
                put(b, at, got + a - p, 4);
            }
        } else if (r.kind == R_X86_64_DTPOFF32 || r.kind == R_X86_64_DTPOFF64) && ctx.shared {
            // An offset in the library's own TLS block, which the module's
            // pair finds at run time.
            let v = s + a - ctx.tls_start;
            if r.kind == R_X86_64_DTPOFF64 { put(b, at, v, 8); }
            else {
                guard fits_signed(v, 32) else { return str("relocation ", k, ": DTPOFF32 out of range"); }
                put(b, at, v, 4);
            }
        } else if (r.kind == R_X86_64_TPOFF32 || r.kind == R_X86_64_TPOFF64) && ctx.shared {
            return str("relocation ", k, ": local-exec TLS in a shared library; recompile with -fPIC");
        } else if r.kind == R_X86_64_GOTTPOFF && ctx.shared {
            guard got != 0 else { return str("relocation ", k, ": no TLS GOT slot for symbol ", r.sym); }
            put(b, at, got + a - p, 4);
        } else if r.kind == R_X86_64_TLSGD && ctx.shared {
            guard global && tlsgds[g] != 0 else { return str("relocation ", k, ": no TLS module and offset pair"); }
            put(b, at, tlsgds[g] + a - p, 4);
        } else if r.kind == R_X86_64_TLSLD && ctx.shared {
            put(b, at, ctx.tlsld_got + a - p, 4);
        } else if r.kind == R_X86_64_TPOFF32 || r.kind == R_X86_64_DTPOFF32 {
            // In an executable a dynamic-TLS offset, after a relaxed local-dynamic
            // sequence, is from the thread pointer as well.
            let v = s + a - tp;
            guard fits_signed(v, 32) else { return str("relocation ", k, ": TPOFF32 out of range"); }
            put(b, at, v, 4);
        } else if r.kind == R_X86_64_TPOFF64 || r.kind == R_X86_64_DTPOFF64 {
            put(b, at, s + a - tp, 8);
        } else if r.kind == R_X86_64_GOTTPOFF {
            if !pre && ie_relaxable(b, at) {
                // mov/add foo@gottpoff(%rip), %reg becomes mov/add $tpoff, %reg.
                let reg = (b[at - 1] >> 3) & 7;
                let mov = b[at - 2] == 0x8b;
                b[at - 3] = 0x48 | ((b[at - 3] & 4) >> 2);   // REX.R becomes REX.B
                b[at - 2] = if mov { 0xc7 } else { 0x81 };
                b[at - 1] = 0xc0 | reg;
                let v = s + a + 4 - tp;
                guard fits_signed(v, 32) else { return str("relocation ", k, ": GOTTPOFF out of range"); }
                put(b, at, v, 4);
            } else {
                guard got != 0 else { return str("relocation ", k, ": no TLS GOT slot for symbol ", r.sym); }
                put(b, at, got + a - p, 4);
            }
        } else if r.kind == R_X86_64_TLSGD {
            // data16 lea x@tlsgd(%rip), %rdi; data16 data16 rex64 call __tls_get_addr
            // becomes mov %fs:0, %rax; lea x@tpoff(%rax), %rax.
            guard matches(b, at - 4, [0x66, 0x48, 0x8d, 0x3d]) && matches(b, at + 4, [0x66, 0x66, 0x48, 0xe8]) else {
                return str("relocation ", k, ": unexpected general-dynamic TLS sequence");
            }
            let seq: u8[12] = [0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0, 0x48, 0x8d, 0x80];
            for x, j in seq { b[at - 4 + j] = x; }
            let v = s + a + 4 - tp;
            guard fits_signed(v, 32) else { return str("relocation ", k, ": TLSGD out of range"); }
            put(b, at + 8, v, 4);
            skip = true;
        } else if r.kind == R_X86_64_TLSLD {
            // lea x@tlsld(%rip), %rdi; call __tls_get_addr becomes
            // data16 data16 data16 mov %fs:0, %rax.
            guard matches(b, at - 3, [0x48, 0x8d, 0x3d]) && matches(b, at + 4, [0xe8]) else {
                return str("relocation ", k, ": unexpected local-dynamic TLS sequence");
            }
            let seq: u8[12] = [0x66, 0x66, 0x66, 0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0];
            for x, j in seq { b[at - 3 + j] = x; }
            skip = true;
        } else {
            return str("relocation ", k, ": type ", r.kind, " is not supported yet");
        }
    }
    return [];
}

// Whether a relocation is one of TLS.
fn is_tls(kind: u32) -> bool {
    kind == R_X86_64_TPOFF32 || kind == R_X86_64_TPOFF64 || kind == R_X86_64_DTPOFF32 || kind == R_X86_64_DTPOFF64 ||
    kind == R_X86_64_GOTTPOFF || kind == R_X86_64_TLSGD || kind == R_X86_64_TLSLD
}
