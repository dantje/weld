// System V / GNU `ar` archives, as libraries come: a view over the bytes,
// verified once by `check`, then walked without copying. Long names come
// from the "//" member, the symbol index from "/" (32-bit) or "/SYM64/".
namespace ar;
import std;

let MAGIC = "!<arch>\n";
let HDR_SIZE = 60;
let SLASH = byte_set("/");
let NUL = byte_set([0 as u8]);

// One member: its name and bytes, both views of the archive. offset is the
// member header's position, which is what the symbol index refers to.
struct Member { name: const u8[:], data: const u8[:], offset: i64 }

fn is_archive(data: const u8[:]) -> bool { starts_with(data, MAGIC) }

fn decimal(field: const u8[:]) -> i64, bool {
    var n = 0;
    var digits = 0;
    for c in field {
        if c == ' ' { break; }
        guard c >= '0' && c <= '9' else { return 0, false; }
        n = n * 10 + (c - '0');
        digits++;
        guard n < 1 << 48 else { return 0, false; }
    }
    return n, digits > 0;
}

// A 60-byte member header's raw name ("/", "//", "/123", "name/",
// "#1/12") and its body's size.
fn parse_header(h: const u8[:]) -> const u8[:], i64, bool {
    guard h.len >= HDR_SIZE && h[58] == '`' && h[59] == '\n' else { return h[..0], 0, false; }
    let size, ok = decimal(h[48..58]);
    return h[..16], size, ok;
}

// The raw name of the member whose header is at pos, where its body
// starts, and its size.
fn header_at(data: const u8[:], pos: i64) -> const u8[:], i64, i64, bool {
    guard pos + HDR_SIZE <= data.len else { return data[..0], 0, 0, false; }
    let raw, size, ok = parse_header(data[pos..pos + HDR_SIZE]);
    guard ok && size <= data.len - pos - HDR_SIZE else { return data[..0], 0, 0, false; }
    return raw, pos + HDR_SIZE, size, true;
}

// The position of the header after a member's body.
fn next_header(at: i64, size: i64) -> i64 { at + size + (size & 1) }

// A member's real name and data, given its raw name and the long-name table.
fn resolve(raw: const u8[:], body: const u8[:], longnames: const u8[:]) -> const u8[:], const u8[:], bool {
    if raw[0] == '/' && raw[1] >= '0' && raw[1] <= '9' {
        let off, ok = decimal(raw[1..]);
        guard ok && off < longnames.len else { return raw[..0], body, false; }
        let rest = longnames[off..];
        let end = find_any(rest, SLASH);
        guard end >= 0 else { return raw[..0], body, false; }
        return rest[..end], body, true;
    }
    if starts_with(raw, "#1/") {          // BSD: the name opens the body
        let n, ok = decimal(raw[3..]);
        guard ok && n <= body.len else { return raw[..0], body, false; }
        let name = body[..n];
        let z = find_any(name, NUL);
        return (if z >= 0 { name[..z] } else { name }), body[n..], true;
    }
    var end = find_any(raw, SLASH);
    if end < 0 { end = trim_end(raw).len; }
    return raw[..end], body, true;
}

fn is_special(raw: const u8[:]) -> bool {
    raw[0] == '/' && (raw[1] == ' ' || raw[1] == '/' || starts_with(raw, "/SYM64/"))
}

// Empty if every header, name and size in data is well formed.
fn check(data: const u8[:]) -> u8[>..] {
    guard is_archive(data) else { return str("not an ar archive"); }
    var longnames = data[..0];
    var pos = MAGIC.len;
    while pos < data.len {
        let raw, at, size, ok = header_at(data, pos);
        guard ok else { return str("bad member header at ", pos); }
        let body = data[at..at + size];
        if starts_with(raw, "// ") { longnames = body; }
        else if !is_special(raw) {
            let _, _, named = resolve(raw, body, longnames);
            guard named else { return str("bad member name at ", pos); }
        }
        pos = next_header(at, size);
    }
    return [];
}

// F(member) for each member of a checked archive, in order, the symbol
// index and the long-name table left out.
fn each_member<F>(data: const u8[:]) {
    var longnames = data[..0];
    var pos = MAGIC.len;
    while pos < data.len {
        let raw, at, size, _ = header_at(data, pos);
        let body = data[at..at + size];
        if starts_with(raw, "// ") { longnames = body; }
        else if !is_special(raw) {
            let name, contents, _ = resolve(raw, body, longnames);
            F(Member { name: name, data: contents, offset: pos });
        }
        pos = next_header(at, size);
    }
}

fn be(b: const u8[:], at: i64, width: i64) -> u64 {
    var v: u64 = 0;
    for k in width { v = (v << 8) | b[at + k]; }
    return v;
}

// The width of the symbol index's words if raw names one: 4 for "/",
// 8 for "/SYM64/"; 0 if it is not a symbol index.
fn index_width(raw: const u8[:]) -> i64 {
    if raw[0] == '/' && raw[1] == ' ' { return 4; }
    if starts_with(raw, "/SYM64/") { return 8; }
    return 0;
}

// F(name, member header offset) for each entry of a symbol index's body,
// whose words are w bytes wide. false if the index is malformed.
fn each_index_entry<F>(body: const u8[:], w: i64) -> bool {
    guard body.len >= w else { return false; }
    let n = be(body, 0, w);
    guard n <= ((body.len - w) / w) as u64 else { return false; }
    let count = n as! i64;
    var names = body[w + count * w..];
    for i in count {
        let z = find_any(names, NUL);
        guard z >= 0 else { return false; }
        F(names[..z], be(body, w + i * w, w) as! i64);
        names = names[z + 1..];
    }
    return true;
}

// F(member) for each member in chunk, a run of whole members read from an
// archive at offset base. Names are raw: a long one is resolved through
// the archive's "//" member, which the chunk need not hold. false if the
// chunk does not hold whole members.
fn each_member_in<F>(chunk: const u8[:], base: i64) -> bool {
    var pos = 0;
    while pos < chunk.len {
        let raw, at, size, ok = header_at(chunk, pos);
        guard ok else { return false; }
        let body = chunk[at..at + size];
        if starts_with(raw, "#1/") {
            let name, contents, named = resolve(raw, body, body[..0]);
            guard named else { return false; }
            F(Member { name: name, data: contents, offset: base + pos });
        } else if !is_special(raw) {
            F(Member { name: raw, data: body, offset: base + pos });
        }
        pos = next_header(at, size);
    }
    return true;
}
