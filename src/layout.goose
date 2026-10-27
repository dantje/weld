// The layout of a static executable: which output section each input
// section joins, where the output sections and segments go, and the ELF
// and program headers. A file offset is always its address less BASE, so
// segments start on page boundaries in the file as in memory.
namespace layout;
import std;
import .elf;

// Output sections, in the order they are laid out, each in a segment:
// read-only (headers, notes, read-only data, unwind tables), executable,
// writable until startup has relocated (RELRO), then writable.
let DISCARD: u8 = 0;
let PROPERTY: u8 = 1;         // .note.gnu.property, made from the inputs' own
let NOTE: u8 = 2;
let DYNAMIC_TABLES: u8 = 3;   // a shared library's .gnu.hash, .dynsym, .dynstr, versions, .rela.dyn
let RODATA: u8 = 4;
let EH_FRAME_HDR: u8 = 5;     // made by the linker
let EH_FRAME: u8 = 6;
let INIT: u8 = 7;
let TEXT: u8 = 8;
let FINI: u8 = 9;
let TDATA: u8 = 10;
let TBSS: u8 = 11;
let PREINIT_ARRAY: u8 = 12;
let INIT_ARRAY: u8 = 13;
let FINI_ARRAY: u8 = 14;
let DATA_RELRO: u8 = 15;      // .data.rel.ro, then the GOT and .dynamic
let DATA: u8 = 16;            // .data, then the IFUNC stubs' slots
let BSS: u8 = 17;
let NONALLOC: u8 = 18;        // debugging information and .comment: in the file, not in memory
let NCLASSES = 19;
let NO_SEGMENT: u8 = 255;
let SEGMENT_OF: u8[NCLASSES] = [0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, NO_SEGMENT];

// The sections not loaded that are kept, by name; a section's key is its
// index here, which makes each name an output section of its own.
let KEPT_NONALLOC = ["", ".debug_abbrev", ".debug_addr", ".debug_aranges", ".debug_frame", ".debug_info",
    ".debug_line", ".debug_line_str", ".debug_loc", ".debug_loclists", ".debug_macinfo", ".debug_macro",
    ".debug_names", ".debug_pubnames", ".debug_pubtypes", ".debug_ranges", ".debug_rnglists", ".debug_str",
    ".debug_str_offsets", ".debug_types", ".debug_gnu_pubnames", ".debug_gnu_pubtypes", ".comment"];

// The key of a kept section that is not loaded; 0 if it is not kept.
fn nonalloc_key(name: const u8[:]) -> u64 {
    for n, i in KEPT_NONALLOC { if i > 0 && n == name { return i as! u64; } }
    return 0;
}
let NSEGMENTS = 4;
let RELRO_SEGMENT = 2;

let SHF_WRITE: u64 = 1;
let SHF_ALLOC: u64 = 2;
let SHF_EXECINSTR: u64 = 4;
let SHF_TLS: u64 = 0x400;
let SHT_NOTE: u32 = 7;
let SHT_INIT_ARRAY: u32 = 14;
let SHT_FINI_ARRAY: u32 = 15;
let SHT_PREINIT_ARRAY: u32 = 16;
let SHT_X86_64_UNWIND: u32 = 0x70000001;

let PT_LOAD: u32 = 1;
let PT_DYNAMIC: u32 = 2;
let PT_INTERP: u32 = 3;
let PT_PHDR: u32 = 6;
let PT_NOTE: u32 = 4;
let PT_TLS: u32 = 7;
let PT_GNU_EH_FRAME: u32 = 0x6474e550;
let PT_GNU_STACK: u32 = 0x6474e551;
let PT_GNU_RELRO: u32 = 0x6474e552;
let PT_GNU_PROPERTY: u32 = 0x6474e553;

// Where the output's first segment goes: 0x400000 for an executable, 0 for
// a shared library, which the dynamic linker places. Main sets it before
// any worker starts, and so before any copies it.
var BASE: u64 = 0x400000;
let PAGE: u64 = 4096;
// Four PT_LOAD, then PT_NOTE twice (8-byte and 4-byte aligned notes),
// PT_GNU_PROPERTY, PT_TLS, PT_GNU_EH_FRAME, PT_GNU_RELRO, PT_DYNAMIC,
// PT_GNU_STACK; one with nothing to cover is PT_NULL. An executable the
// dynamic linker loads has PT_PHDR and PT_INTERP first, two more: main
// sets NPHDRS for it, before it lays out.
var NPHDRS = 12;
fn headers_size() -> u64 { 64 + 56 * NPHDRS as! u64 }

fn align_up(x: u64, a: u64) -> u64 { if a <= 1 { x } else { (x + a - 1) & (0 - a) } }

// The output section an input section joins. Of the notes, those of
// 4-byte alignment are copied; .note.gnu.property is merged instead, and
// what is aligned otherwise left out.
fn classify(name: const u8[:], s: elf::Section) -> u8 {
    if s.flags & SHF_ALLOC == 0 { return if nonalloc_key(name) > 0 && s.kind != elf::SHT_NOBITS { NONALLOC } else { DISCARD }; }
    if s.kind == SHT_NOTE { return if name != ".note.gnu.property" && s.align <= 4 { NOTE } else { DISCARD }; }
    if s.kind == SHT_INIT_ARRAY || starts_with(name, ".init_array") { return INIT_ARRAY; }
    if s.kind == SHT_FINI_ARRAY || starts_with(name, ".fini_array") { return FINI_ARRAY; }
    if s.kind == SHT_PREINIT_ARRAY { return PREINIT_ARRAY; }
    if s.flags & SHF_TLS != 0 { return if s.kind == elf::SHT_NOBITS { TBSS } else { TDATA }; }
    if name == ".init" { return INIT; }
    if name == ".fini" { return FINI; }
    if s.kind == SHT_X86_64_UNWIND || name == ".eh_frame" { return EH_FRAME; }
    if s.flags & SHF_EXECINSTR != 0 { return TEXT; }
    if s.flags & SHF_WRITE != 0 {
        if s.kind == elf::SHT_NOBITS { return BSS; }
        return if name == ".data.rel.ro" || starts_with(name, ".data.rel.ro.") { DATA_RELRO } else { DATA };
    }
    return RODATA;
}

// An output section: its address, size and alignment.
struct Out { addr: u64, size: u64, align: u64 }
struct Segment { addr: u64, filesz: u64, memsz: u64, flags: u32 }
// The segments and where the file ends.
struct Image { load: Segment[NSEGMENTS], tls: Segment, tls_align: u64, file_size: u64 }

// Gives each output section an address, given its size and alignment.
fn assign(outs: Out[NCLASSES]&) -> Image {
    var img = Image { load: [Segment { addr: 0, filesz: 0, memsz: 0, flags: 0 }; NSEGMENTS],
                      tls: Segment { addr: 0, filesz: 0, memsz: 0, flags: 4 }, tls_align: 1, file_size: 0 };
    img.load[0] = Segment { addr: BASE, filesz: headers_size(), memsz: headers_size(), flags: 4 };
    img.load[1].flags = 5;
    img.load[2].flags = 6;
    img.load[3].flags = 6;
    var at = BASE + headers_size();
    var seg = 0;
    for c in 1..NCLASSES {
        if SEGMENT_OF[c] == NO_SEGMENT { continue; }
        let k: i64 = SEGMENT_OF[c];
        if k != seg {
            seg = k;
            at = align_up(at, PAGE);
            img.load[k].addr = at;
        }
        let o .= outs[c];
        o.addr = align_up(at, o.align);
        if c == TBSS {             // takes no room in the image, only in each thread's block
            continue;
        }
        at = o.addr + o.size;
        img.load[k].memsz = at - img.load[k].addr;
        if c != BSS { img.load[k].filesz = img.load[k].memsz; }
    }
    if outs[TDATA].size + outs[TBSS].size > 0 {
        let start = if outs[TDATA].size > 0 { outs[TDATA].addr } else { outs[TBSS].addr };
        img.tls = Segment { addr: start, filesz: outs[TDATA].size, memsz: outs[TBSS].addr + outs[TBSS].size - start, flags: 4 };
        img.tls_align = max(outs[TDATA].align, outs[TBSS].align);
    }
    let last = if img.load[3].memsz > 0 { 3 } else { 2 };
    img.file_size = img.load[last].addr - BASE + img.load[last].filesz;
    return img;
}

fn le(out: u8[>..]&, v: u64, n: i64) { for k in n { out.push((v >> (8 * k)) as! u8); } }

fn phdr(out: u8[>..]&, kind: u32, flags: u32, addr: u64, filesz: u64, memsz: u64, align: u64) {
    if memsz == 0 && kind != PT_GNU_STACK {          // nothing to cover
        for k in 56 { out.push(0); }
        return;
    }
    le(out, kind, 4); le(out, flags, 4);
    le(out, if addr >= BASE { addr - BASE } else { 0 }, 8);
    le(out, addr, 8); le(out, addr, 8);
    le(out, filesz, 8); le(out, memsz, 8); le(out, align, 8);
}

// The ELF header and program headers, headers_size() bytes; the section
// headers are shnum at shoff, the names' table section shstrndx.
// With gnu, the OS ABI is GNU's, which IFUNC symbols take.
// With relro, the RELRO segment is made read-only once startup has relocated.
// Output the dynamic linker relocates (dyn) is ET_DYN, its .dynamic at
// dynamic, dynamic_size bytes; a PIE executable's interpreter's name is at
// interp, interp_size bytes, 0 for none.
fn headers(img: const Image&, outs: const Out[NCLASSES]&, entry: u64, shoff: u64, shnum: i64, shstrndx: i64, gnu: bool,
           relro: bool, dyn: bool, dynamic: u64, dynamic_size: u64, interp: u64, interp_size: u64) -> u8[>..] {
    var out: u8[>..] = [];
    out.append("\x7fELF");
    out.push(2); out.push(1); out.push(1);              // 64-bit, little-endian, version 1
    out.push(if gnu { 3 } else { 0 });
    for k in 8 { out.push(0); }
    le(out, if dyn { 3 } else { 2 }, 2);               // ET_DYN, ET_EXEC
    le(out, elf::EM_X86_64, 2);
    le(out, 1, 4);
    le(out, entry, 8);
    le(out, 64, 8);                                     // program headers follow
    le(out, shoff, 8);
    le(out, 0, 4);
    le(out, 64, 2); le(out, 56, 2); le(out, NPHDRS as! u64, 2);
    le(out, 64, 2); le(out, shnum as! u64, 2); le(out, shstrndx as! u64, 2);
    if interp_size > 0 {
        phdr(out, PT_PHDR, 4, BASE + 64, 56 * NPHDRS as! u64, 56 * NPHDRS as! u64, 8);
        phdr(out, PT_INTERP, 4, interp, interp_size, interp_size, 1);
    }
    for s in img.load { phdr(out, PT_LOAD, s.flags, s.addr, s.filesz, s.memsz, PAGE); }
    let p = outs[PROPERTY];
    let n = outs[NOTE];
    phdr(out, PT_NOTE, 4, p.addr, p.size, p.size, 8);
    phdr(out, PT_NOTE, 4, n.addr, n.size, n.size, 4);
    phdr(out, PT_GNU_PROPERTY, 4, p.addr, p.size, p.size, 8);
    phdr(out, PT_TLS, 4, img.tls.addr, img.tls.filesz, img.tls.memsz, img.tls_align);
    let h = outs[EH_FRAME_HDR];
    phdr(out, PT_GNU_EH_FRAME, 4, h.addr, h.size, h.size, 4);
    // RELRO ends on a page: the next segment starts on one.
    let r = img.load[RELRO_SEGMENT];
    phdr(out, PT_GNU_RELRO, 4, r.addr, r.filesz, if relro { align_up(r.memsz, PAGE) } else { 0 }, 1);
    phdr(out, PT_DYNAMIC, 6, dynamic, dynamic_size, dynamic_size, 8);
    phdr(out, PT_GNU_STACK, 6, 0, 0, 0, 16);            // not executable
    return out;
}

// Output section names, kinds and flags, by class.
let NAMES = ["", ".note.gnu.property", ".note", "", ".rodata", ".eh_frame_hdr", ".eh_frame", ".init", ".text", ".fini",
             ".tdata", ".tbss", ".preinit_array", ".init_array", ".fini_array", ".data.rel.ro", ".data", ".bss", ""];
let KINDS: u32[NCLASSES] = [0, 7, 7, 0, 1, 1, 1, 1, 1, 1, 1, 8, 16, 14, 15, 1, 1, 8, 1];
let FLAGS: u64[NCLASSES] = [0, 2, 2, 2, 2, 2, 2, 6, 6, 6, 0x403, 0x403, 3, 3, 3, 3, 3, 3, 0];

// A section header of the output.
struct Shdr { name: u32, kind: u32, flags: u64, addr: u64, offset: u64, size: u64, link: u32, info: u32,
              align: u64, entsize: u64 }

fn shdr(out: u8[>..]&, h: Shdr) {
    le(out, h.name, 4); le(out, h.kind, 4); le(out, h.flags, 8); le(out, h.addr, 8); le(out, h.offset, 8);
    le(out, h.size, 8); le(out, h.link, 4); le(out, h.info, 4); le(out, h.align, 8); le(out, h.entsize, 8);
}
