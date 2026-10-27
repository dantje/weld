// Reading .eh_frame: its records are CIEs and FDEs, each a 4-byte length
// and a 4-byte CIE pointer (0 for a CIE), up to a zero-length terminator.
// An FDE's first field is the start of the code it describes, encoded as
// its CIE's augmentation says ('R'); .eh_frame_hdr's table is those starts.
namespace eh;
import std;
import .elf;

fn u32at(b: const u8[:], at: i64) -> u64 { elf::u32le(b[at..at + 4], 0) }

// The number of FDEs in an input section's bytes.
fn count_fdes(b: const u8[:]) -> i64 {
    var n = 0;
    var pos = 0;
    while pos + 8 <= b.len {
        let length = u32at(b, pos) as! i64;
        if length == 0 || length == 0xffffffff || length > b.len - pos - 4 { break; }
        if u32at(b, pos + 4) != 0 { n++; }
        pos += 4 + length;
    }
    return n;
}

fn uleb(b: const u8[:], at: i64&) -> u64 {
    var v: u64 = 0;
    var shift = 0;
    while at < b.len {
        let c = b[at];
        at++;
        if shift < 64 { v |= ((c & 0x7f) as u64) << shift; }
        shift += 7;
        if c & 0x80 == 0 { break; }
    }
    return v;
}

// The size of a pointer of encoding enc; 0 if it is not one this reads.
fn pointer_size(enc: u8) -> i64 {
    let f = enc & 0x0f;
    if f == 0x00 || f == 0x04 || f == 0x0c { return 8; }
    if f == 0x03 || f == 0x0b { return 4; }
    if f == 0x02 || f == 0x0a { return 2; }
    return 0;
}

// The FDE pointer encoding the CIE at cie gives, or 0xff if it cannot be read.
fn fde_encoding(b: const u8[:], cie: i64) -> u8 {
    guard cie >= 0 && cie + 9 <= b.len else { return 0xff; }
    let end = cie + 4 + u32at(b, cie) as! i64;
    guard end <= b.len else { return 0xff; }
    var at = cie + 8;
    let version = b[at];
    at++;
    let aug_at = at;
    while at < end && b[at] != 0 { at++; }
    let aug = b[aug_at..at];
    at++;
    uleb(b, at);                                    // code alignment
    uleb(b, at);                                    // data alignment (signed; only skipped)
    if version == 1 { at++; } else { uleb(b, at); }  // return address register
    if aug.len == 0 || aug[0] != 'z' { return 0; }   // no augmentation data: absolute pointers
    uleb(b, at);
    for c in aug[1..] {
        guard at < end else { return 0xff; }
        if c == 'R' { return b[at]; }
        if c == 'P' {
            let enc = b[at];
            let n = pointer_size(enc);
            guard n > 0 else { return 0xff; }
            at += 1 + n;
        } else if c == 'L' {
            at++;
        } else if c != 'S' && c != 'B' {
            return 0xff;
        }
    }
    return 0;
}

// For each FDE in b, a relocated .eh_frame section at addr, the address of
// the code it describes and its own address, appended to pairs.
fn fde_starts(b: const u8[:], addr: u64, pairs: u64[>..]&) {
    var pos = 0;
    var cie = -1;
    var enc: u8 = 0xff;
    while pos + 8 <= b.len {
        let length = u32at(b, pos) as! i64;
        if length == 0 || length == 0xffffffff || length > b.len - pos - 4 { break; }
        let id = u32at(b, pos + 4) as! i64;
        if id != 0 && pos + 8 + 8 <= b.len {
            let c = pos + 4 - id;
            if c != cie { cie = c; enc = fde_encoding(b, c); }
            let n = if enc == 0xff { 0 } else { pointer_size(enc) };
            if n > 0 {
                var v: u64 = 0;
                for k in n { v |= (b[pos + 8 + k] as u64) << (8 * k); }
                if n < 8 && enc & 0x08 != 0 && v >> (8 * n - 1) & 1 != 0 { v |= 0 - (1 << (8 * n)); }    // signed
                if enc & 0x70 == 0x10 { v += addr + (pos + 8) as! u64; }                                // pcrel
                pairs.push(v);
                pairs.push(addr + pos as! u64);
            }
        }
        pos += 4 + length;
    }
}

// The records of the .eh_frame section b, its relocations rela (none if
// nrela is 0): for each, its offset, its length with the length field, and
// for an FDE the index of the relocation of the start of its code, else -1;
// three values a record, in recs. Up to a zero-length terminator, which is
// not a record. False, with no records, if the relocations' offsets do not
// ascend or the records cannot be read: then no FDE is left out.
fn records(o: const elf::Object&, b: const u8[:], rela: elf::Section, nrela: i64, recs: i64[>..]&) -> bool {
    for k in 1..nrela { if elf::rela(o, rela, k).offset < elf::rela(o, rela, k - 1).offset { return false; } }
    var pos = 0;
    var k = 0;
    while pos + 8 <= b.len {
        let length = u32at(b, pos) as! i64;
        if length == 0 { break; }
        guard length != 0xffffffff && length <= b.len - pos - 4 else { recs.clear(); return false; }
        var start = -1;
        if u32at(b, pos + 4) != 0 {
            let at = (pos + 8) as! u64;
            while k < nrela && elf::rela(o, rela, k).offset < at { k++; }
            if k < nrela && elf::rela(o, rela, k).offset == at { start = k; }
        }
        recs.push(pos);
        recs.push(4 + length);
        recs.push(start);
        pos += 4 + length;
    }
    return true;
}
