// A shared library's tables for the dynamic linker, from what main decided:
// .gnu.hash, .gnu.version_r, .dynamic and the run-time relocations.
namespace dynamic;
import std;
import .layout;

let DT_NULL: u64 = 0;
let DT_NEEDED: u64 = 1;
let DT_STRTAB: u64 = 5;
let DT_SYMTAB: u64 = 6;
let DT_RELA: u64 = 7;
let DT_RELASZ: u64 = 8;
let DT_RELAENT: u64 = 9;
let DT_STRSZ: u64 = 10;
let DT_SYMENT: u64 = 11;
let DT_INIT: u64 = 12;
let DT_FINI: u64 = 13;
let DT_SONAME: u64 = 14;
let DT_INIT_ARRAY: u64 = 25;
let DT_FINI_ARRAY: u64 = 26;
let DT_INIT_ARRAYSZ: u64 = 27;
let DT_FINI_ARRAYSZ: u64 = 28;
let DT_RUNPATH: u64 = 29;
let DT_FLAGS: u64 = 30;
let DT_GNU_HASH: u64 = 0x6ffffef5;
let DT_VERSYM: u64 = 0x6ffffff0;
let DT_FLAGS_1: u64 = 0x6ffffffb;
let DT_VERNEED: u64 = 0x6ffffffe;
let DT_VERNEEDNUM: u64 = 0x6fffffff;
let DF_BIND_NOW: u64 = 8;
let DF_STATIC_TLS: u64 = 0x10;
let DF_1_NOW: u64 = 1;
let DF_1_PIE: u64 = 0x08000000;
let DT_DEBUG: u64 = 21;

let R_X86_64_64: u64 = 1;
let R_X86_64_COPY: u64 = 5;
let R_X86_64_GLOB_DAT: u64 = 6;
let R_X86_64_RELATIVE: u64 = 8;
let R_X86_64_DTPMOD64: u64 = 16;
let R_X86_64_DTPOFF64: u64 = 17;
let R_X86_64_TPOFF64: u64 = 18;
let R_X86_64_IRELATIVE: u64 = 37;

// An Elf64_Rela: where, of what type against which dynamic symbol, plus what.
fn rela(out: u8[>..]&, offset: u64, kind: u64, sym: u64, addend: u64) {
    layout::le(out, offset, 8);
    layout::le(out, sym << 32 | kind, 8);
    layout::le(out, addend, 8);
}

// How many buckets .gnu.hash has for n symbols: some four a bucket.
fn buckets(n: i64) -> i64 { max(1, n / 4) }

// .gnu.hash for the dynamic symbols from symoffset on, whose hashes are
// given in their order, which is by bucket (hash % buckets(n)).
fn gnu_hash(hashes: const u32[:], symoffset: i64) -> u8[>..] {
    let n = hashes.len;
    let nb = buckets(n);
    var words = 1;                       // the Bloom filter: some 12 bits a symbol, a power of two of words
    while words * 64 < n * 12 { words *= 2; }
    let shift: u32 = 26;
    var bloom: u64[>..] = [];
    bloom.resize(words, 0);
    var first: u32[>..] = [];            // each bucket's first symbol, 0 if none
    first.resize(nb, 0);
    for h, i in hashes {
        let one: u64 = 1;
        let w: i64 = (h / 64) % words;
        bloom[w] |= (one << (h % 64)) | (one << ((h >> shift) % 64));
        let b: i64 = h % nb;
        if first[b] == 0 { first[b] = (symoffset + i) as! u32; }
    }
    var out: u8[>..] = [];
    layout::le(out, nb as! u64, 4); layout::le(out, symoffset as! u64, 4);
    layout::le(out, words as! u64, 4); layout::le(out, shift, 4);
    for w in bloom { layout::le(out, w, 8); }
    for f in first { layout::le(out, f, 4); }
    for h, i in hashes {                 // the chain: the hash, its low bit marking a bucket's last
        let last = i + 1 == n || hashes[i + 1] % nb != h % nb;
        layout::le(out, if last { h | 1 } else { h & ~1 }, 4);
    }
    return out;
}

// The ELF hash a version's name has in .gnu.version_r.
fn elf_hash(name: const u8[:]) -> u32 {
    var h: u32 = 0;
    for c in name {
        h = (h << 4) + c;
        let g = h & 0xf0000000;
        if g != 0 { h ^= g >> 24; }
        h &= ~g;
    }
    return h;
}

// One version the library needs of another: the library's name and the
// version's, as .dynstr offsets, the version's own name for its hash, and
// the index .gnu.version gives the symbols of it.
struct Need { file: u32, name: u32, hash: u32, index: u16 }

// .gnu.version_r from needs, those of one library together; and how many
// libraries it names.
fn version_r(needs: const Need[:]) -> u8[>..], i64 {
    var out: u8[>..] = [];
    var files = 0;
    var i = 0;
    while i < needs.len {
        var j = i;
        while j < needs.len && needs[j].file == needs[i].file { j++; }
        files++;
        layout::le(out, 1, 2);                                       // vn_version
        layout::le(out, (j - i) as! u64, 2);                         // vn_cnt
        layout::le(out, needs[i].file, 4);                           // vn_file
        layout::le(out, 16, 4);                                      // vn_aux: right after
        layout::le(out, if j < needs.len { 16 + 16 * (j - i) as! u64 } else { 0 }, 4);   // vn_next
        for k in i..j {
            layout::le(out, needs[k].hash, 4);
            layout::le(out, 0, 2);
            layout::le(out, needs[k].index, 2);
            layout::le(out, needs[k].name, 4);
            layout::le(out, if k + 1 < j { 16 } else { 0 }, 4);
        }
        i = j;
    }
    return out, files;
}

// Appends a .dynamic entry.
fn entry(out: u8[>..]&, tag: u64, value: u64) { layout::le(out, tag, 8); layout::le(out, value, 8); }
