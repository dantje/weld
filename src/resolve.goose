// Symbol resolution, on workers that share nothing.
//
// The global symbol table is split by hash over up to MAX_SHARDS shard
// workers, each a long-lived program owning its part; ToShard<u8[k]> is the
// queue of shard k - 1, so a message reaches exactly one shard. How many
// shards and parse workers run follows from the size of the inputs, since
// starting a thread costs about as much as reading a megabyte. Parse workers read
// objects and archive symbol indexes and send every global symbol to its
// shard, one batch per shard per job. Main runs the rounds: after each,
// a flush asks every shard which archive members would define a symbol
// that is referenced but not defined; main has those members parsed, and
// stops when a round extracts nothing. Shards decide only at a flush,
// over everything sent before it, so the outcome does not depend on the
// order messages arrive in.
namespace resolve;
import std;
import .elf;
import .xxh3;
import .merge;
import .layout;
import .symbols;
import .reloc;
import dictionary;

let MAX_SHARDS = 16;

// The shard of a hash, out of n: its top bits scaled to n.
fn shard_of(h: u64, n: i64) -> i64 { (((h >> 32) * n as u64) >> 32) as! i64 }

// One occurrence of a global symbol. shndx, value and stype matter for a definition.
struct Entry { hash: u64, prio: u64, size: u64, value: u64, sym: u32, shndx: u32, kind: u8, stype: u8, bind: u8,
               other: u8, need: u8, name: u8[varint] }

let CMD_SYMBOLS: u8 = 0;
let CMD_FLUSH: u8 = 1;
let CMD_FINISH: u8 = 2;
let CMD_EXPORT: u8 = 3;      // arg: the global id of the shard's first symbol
// For an executable, before finish: which shared libraries' data a direct
// reference needs copied (the answer is CopyKeys); then which is copied
// (each entry's prio and value: a library and an address in it).
let CMD_COPY_KEYS: u8 = 4;
let CMD_COPY: u8 = 5;
struct ToShard<T> { cmd: u8, arg: i64, entries: Entry[>..] }

// A shard's answer to a flush: the members to extract, as prios.
struct Flushed { shard: i64, extract: u64[>..] }

// A shard's answer to CMD_COPY_KEYS: for each shared library's data object
// that an object refers to directly (reloc::NEED_COPY), its definition's prio
// and value, in pairs.
struct CopyKeys { shard: i64, keys: u64[>..] }

// A shard's answer to finish, with what its part of the output's symbol
// table will take: its hidden symbols, which become local, and the rest.
struct Final { shard: i64, symbols: i64, defined: i64, undefined: i64, duplicates: i64, digest: u64,
               locals: i64, local_strs: i64, globals: i64, global_strs: i64,
               shlib_undefined: i64,
               names: u8[>..] }   // "U name", "D name" or "S name file" lines, the first 4 KB
// shlib_undefined: what given shared libraries use that nothing defines
// for them (S lines, with the file of the first that uses it).

// After export, where a shard writes its symbols, and their values in the
// order of its symbols; the answer is SymtabDone.
// A symbol that is also in the dynamic symbol table has a dyn_index there,
// its name at dyn_name in .dynstr and its version index; dyn_index 0 is
// none. The tables are at dynsym_at, dynstr_at and versym_at, if any.
struct SymVal { value: u64, shndx: u16, stype: u8, dyn_index: u32, dyn_name: u32, version: u16 }
// hash_id: what the shard writes goes into a build-ID sum, which
// SymtabDone reports as ida and idb (xxh3::IdSum).
struct Symtab<T> { out: i32, symtab_at: i64, strtab_at: i64, local_index: i64, global_index: i64,
                   local_str: i64, global_str: i64, dynsym_at: i64, dynstr_at: i64, versym_at: i64,
                   hash_id: bool, values: SymVal[>..] }
struct SymtabDone { shard: i64, ok: bool, ida: u64, idb: u64 }

// Merging strings (merge.goose). A worker sends a shard the strings of an
// object whose hashes pick it, in data: each its u32 merge group and index
// among the object's strings, which number them section after section,
// its u32 length and u64 hash, then its bytes. After export, main tells
// each shard how many such messages it got (Merge), and the shard answers
// with MergeDone: in data, the number of groups and each group with the
// size of the shard's part of it, then runs of strings by prio and index,
// each run of one object and group: its prio and group << 32 | count, then
// count strings, each its index << 32 | its offset in the shard's part. Before the symbol table, main
// tells the shard where in the file each of its parts goes (MergeAt: group
// and offset pairs), and the shard writes them.
struct Strings<T> { prio: u64, data: u8[>..] }
struct Merge<T> { count: i64 }
struct MergeDone { shard: i64, data: u64[>..] }
struct MergeAt<T> { at: u64[>..] }
// A string on its way to a shard: its group, index in the object, hash and
// bytes, a view of the job's buffer.
struct StrRec { group: u32, index: u32, hash: u64, bytes: const u8[:] }
// A string a shard keeps: its group, its bytes in the shard's arena, its
// first use and its offset in the shard's part of the group.
struct Uniq { group: u32, len: u32, at: u64, hash: u64, prio: u64, index: u32, offset: u64 }
// A use of one: which object and string, and which Uniq.
struct Use { prio: u64, index: u32, u: u32 }

// A shard's answer to export: what defines each of its symbols, in the
// order of their global ids, and the global id of every occurrence.
// vis is the most constraining visibility of all occurrences; strong if a
// reference is not weak; in_dso if a shared library defines or refers to
// it; gnu_hash and name_len are the name's, for the dynamic symbol table.
// A shared library's symbol has its version index as its shndx.
struct Def { prio: u64, value: u64, size: u64, sym: u32, shndx: u32, kind: u8, stype: u8, need: u8, defined: bool,
             vis: u8, bind: u8, referenced: bool, strong: bool, in_dso: bool, gnu_hash: u32, name_len: u32,
             copied: bool }
struct Defs { shard: i64, defs: Def[>..] }
struct Occ { prio: u64, sym: u32, id: u32 }
struct Occs { shard: i64, occs: Occ[>..] }
// The groups whose sections are left out: those of every copy but the kept one.
struct Losers { shard: i64, groups: Occ[>..] }

// A slot of a shard's open-addressed table of symbols: the tag of the
// name's hash (tag, never 0; 0 is an empty slot) and the symbol's index.
struct Slot { tag: u32, sym: u32 }

extern fn ld_pwrite(fd: i32, offset: i64, data: const u8[:]) -> bool;

// The GNU hash of a name, which .gnu.hash is built from.
fn gnu_hash(name: const u8[:]) -> u32 {
    var h: u32 = 5381;
    for c in name { h = h * 33 + c; }
    return h;
}

// Appends an Elf64_Sym.
fn elf_symbol(out: u8[>..]&, name: u32, info: u8, other: u8, shndx: u16, value: u64, size: u64) {
    for k in 4 { out.push((name >> (8 * k)) as! u8); }
    out.push(info);
    out.push(other);
    out.push(shndx as! u8); out.push((shndx >> 8) as! u8);
    for k in 8 { out.push((value >> (8 * k)) as! u8); }
    for k in 8 { out.push((size >> (8 * k)) as! u8); }
}

fn tag(h: u64) -> u32 { (h as! u32) | 0x80000000 }

fn shard_loop<T>(marker: T, shard: i64) {
    var names: u8[>..] = [];
    var syms: Sym[>..] = [];
    var slots: Slot[>..<] = [];
    var pending: u32[>..<] = [];
    var occs: Occ[>..] = [];         // every occurrence in an object; id is the entry until export
    var order: u32[>..] = [];        // from export on, the entries in the order of their global ids
    var place_of: u32[>..] = [];     // and each entry's place in that order
    var str_bytes: u8[>..] = [];     // merging strings: each kept once
    var uniqs: Uniq[>..] = [];
    var str_slots: u32[>..] = [];    // open addressing over uniqs, index + 1
    var uses: Use[>..] = [];
    var blocks: Use[>..] = [];       // each message's uses: prio, and index the first, u the end
    var by_offset: u32[>..] = [];    // uniqs, by group and first use

    fn str_place(i: i64) {
        let mask = str_slots.len - 1;
        var q = (uniqs[i].hash & mask as u64) as! i64;
        while str_slots[q] != 0 { q = (q + 1) & mask; }
        str_slots[q] = (i + 1) as! u32;
    }
    // The Uniq of string b of group g with hash h, added if new.
    fn str_find(g: u32, h: u64, b: const u8[:]) -> i64 {
        if (uniqs.len + 1) * 2 > str_slots.len {
            str_slots.resize(max(4096, str_slots.len * 2), 0);
            for q in str_slots.len { str_slots[q] = 0; }
            for i in uniqs.len { str_place(i); }
        }
        let mask = str_slots.len - 1;
        var q = (h & mask as u64) as! i64;
        loop {
            let x = str_slots[q];
            if x == 0 { break; }
            let u = uniqs[x - 1];
            if u.hash == h && u.group == g && u.len == b.len as! u32 &&
               str_bytes[(u.at as! i64)..(u.at as! i64) + b.len] == b { return (x - 1) as! i64; }
            q = (q + 1) & mask;
        }
        let at = str_bytes.len;
        str_bytes.append(b);
        uniqs.push(Uniq { group: g, len: b.len as! u32, at: at as! u64, hash: h, prio: 0xffffffffffffffff, index: 0,
                          offset: 0 });
        str_slots[q] = uniqs.len as! u32;
        return uniqs.len - 1;
    }
    // Takes count messages of strings, keeps one copy of each, and answers
    // main (MergeDone).
    fn merge_strings(count: i64) {
        for c in count {
            let m = qget<Strings<T>>();
            let first = uses.len;
            var k = 0;
            while k + 20 <= m.data.len {
                let head = m.data[k..k + 20];
                let g = elf::u32le(head, 0);
                let index = elf::u32le(head, 4);
                let len = elf::u32le(head, 8) as! i64;
                let h = elf::u64le(head, 12);
                let b = m.data[k + 20..k + 20 + len];
                k += 20 + len;
                let u = str_find(g, h, b);
                let y .= uniqs[u];
                if m.prio < y.prio || (m.prio == y.prio && index < y.index) { y.prio = m.prio; y.index = index; }
                uses.push(Use { prio: m.prio, index: index, u: u as! u32 });
            }
            blocks.push(Use { prio: m.prio, index: first as! u32, u: uses.len as! u32 });
        }
        // Each group's strings in the order of their first use, each at
        // its alignment.
        for i in uniqs.len { by_offset.push(i as! u32); }
        sort(by_offset) { a, b =>
            let x .= uniqs[a];
            let y .= uniqs[b];
            x.group < y.group || (x.group == y.group && (x.prio < y.prio || (x.prio == y.prio && x.index < y.index)))
        };
        var done = MergeDone { shard: shard, data: [] };
        var groups: u64[>..] = [];       // group and size pairs
        var size: u64 = 0;
        for i, j in by_offset {
            let y .= uniqs[i];
            if j == 0 || uniqs[by_offset[j - 1]].group != y.group {
                if j > 0 { groups.push(size); }
                groups.push(y.group);
                size = 0;
            }
            size = layout::align_up(size, merge::align_of(y.group));
            y.offset = size;
            size += y.len;
        }
        if by_offset.len > 0 { groups.push(size); }
        done.data.push((groups.len / 2) as! u64);
        done.data.append(groups);
        // By object: a message holds one object's uses, in the order of
        // their indexes already.
        sort(blocks) { a, b => a.prio < b.prio };
        for &blk in blocks {
            var i = blk.index as! i64;
            let end = blk.u as! i64;
            while i < end {
                let g = uniqs[uses[i].u].group;
                var j = i;
                while j < end && uniqs[uses[j].u].group == g { j++; }
                done.data.push(blk.prio);
                done.data.push((g as u64) << 32 | (j - i) as! u64);
                for k in i..j { done.data.push((uses[k].index as u64) << 32 | uniqs[uses[k].u].offset); }
                i = j;
            }
        }
        qput(done);
    }

    fn place(i: i64) {
        let mask = slots.len - 1;
        var q = (syms[i].hash & mask as u64) as! i64;
        while slots[q].tag != 0 { q = (q + 1) & mask; }
        slots[q] = Slot { tag: tag(syms[i].hash), sym: i as! u32 };
    }
    fn grow() {
        let cap = max(1024, slots.len * 2);
        slots.resize(cap, Slot { tag: 0, sym: 0 });
        for q in slots.len { slots[q] = Slot { tag: 0, sym: 0 }; }
        for i in syms.len { place(i); }
    }
    // The symbol's index, made if it is not there, unless only_if_there:
    // then -1.
    fn lookup(e: const Entry&, only_if_there: bool) -> i64 {
        if (syms.len + 1) * 3 > slots.len * 2 { grow(); }
        let t = tag(e.hash);
        let mask = slots.len - 1;
        var q = (e.hash & mask as u64) as! i64;
        loop {
            let s = slots[q];
            if s.tag == 0 { break; }
            if s.tag == t {
                let y = syms[s.sym];
                if y.hash == e.hash && names[y.name_at..y.name_at + y.name_len] == e.name { return s.sym; }
            }
            q = (q + 1) & mask;
        }
        if only_if_there { return -1; }
        let i = syms.len;
        syms.push(Sym { hash: e.hash, name_at: names.len as! u32, name_len: e.name.len as! u32,
                        def_prio: 0, def_size: 0, def_value: 0, def_sym: 0, def_shndx: 0, def_kind: 0, def_stype: 0,
                        def_bind: 0, def_other: 0, vis: 0, need: 0, defined: false, referenced: false,
                        lazy_prio: 0, has_lazy: false, strong_ref: false, requested: false,
                        pending: false, duplicate: false, in_dso: false, occurs: false, shlib_ref: false,
                        def_any: false, shlib_prio: 0, copied: false });
        names.append(e.name);
        slots[q] = Slot { tag: t, sym: i as! u32 };
        return i;
    }
    fn add(e: const Entry&) {
        if e.kind == INDIRECT || e.kind == INDIRECT_DEF {
            let k = lookup(e, true);
            if k >= 0 { syms[k].in_dso = true; syms[k].def_any = syms[k].def_any || e.kind == INDIRECT_DEF; }
            return;
        }
        let i = lookup(e, false);
        let s .= syms[i];
        if e.kind == SHLIB_DEF { s.def_any = true; return; }
        if e.kind == DSO_REF {                                // nothing more: no archive member is taken for it
            s.in_dso = true;
            if e.bind != 2 && (!s.shlib_ref || e.prio < s.shlib_prio) { s.shlib_ref = true; s.shlib_prio = e.prio; }
            return;
        }
        if e.kind == SHARED { s.in_dso = true; s.def_any = true; }   // which a library may use, if an object's hidden one wins
        if e.kind != LAZY && e.kind != START && e.kind != STOP && e.kind != SHARED {     // an object's
            occs.push(Occ { prio: e.prio, sym: e.sym, id: i as! u32 });
            s.occurs = true;
        }
        s.need |= e.need;
        if e.kind != LAZY && e.kind != GROUP && constraint(e.other & 3) > constraint(s.vis) { s.vis = e.other & 3; }
        // The linker's own weak references (prio 0: the entry, _init, _fini)
        // look for a symbol without making it one the output uses.
        if e.kind == UNDEF_WEAK { if e.prio != 0 { s.referenced = true; } return; }
        if e.kind == UNDEF {
            s.strong_ref = true;
            s.referenced = true;
            if (!s.defined || s.def_kind == SHARED) && !s.pending { s.pending = true; pending.push(i as! u32); }
            return;
        }
        if e.kind == GROUP {
            if !s.defined || e.prio < s.def_prio { s.defined = true; s.def_kind = GROUP; s.def_prio = e.prio; }
            return;
        }
        if e.kind == LAZY {
            if !s.has_lazy || e.prio < s.lazy_prio { s.has_lazy = true; s.lazy_prio = e.prio; }
            return;
        }
        if !s.defined {
            s.defined = true;
            s.def_kind = e.kind; s.def_prio = e.prio; s.def_sym = e.sym; s.def_size = e.size;
            s.def_value = e.value; s.def_shndx = e.shndx; s.def_stype = e.stype; s.def_other = e.other;
            s.def_bind = e.bind;
            return;
        }
        let r = rank(e.kind);
        let held = rank(s.def_kind);
        if r == held && e.kind == DEF && s.def_kind == DEF && e.prio != s.def_prio { s.duplicate = true; }
        let wins = if r != held { r > held }
                   else if e.kind == COMMON { e.size > s.def_size || (e.size == s.def_size && e.prio < s.def_prio) }
                   else { e.prio < s.def_prio };
        if wins {
            let size = if e.kind == COMMON && s.def_kind == COMMON { max(e.size, s.def_size) } else { e.size };
            s.def_kind = e.kind; s.def_prio = e.prio; s.def_sym = e.sym; s.def_size = size;
            s.def_value = if e.kind == COMMON && s.def_kind == COMMON { max(e.value, s.def_value) } else { e.value };
            s.def_shndx = e.shndx; s.def_stype = e.stype; s.def_other = e.other; s.def_bind = e.bind;
        } else if e.kind == COMMON && s.def_kind == COMMON {     // the largest size, the strictest alignment
            s.def_size = max(e.size, s.def_size);
            s.def_value = max(e.value, s.def_value);
        }
    }

    // Writes the symbols this shard emits into the output's symbol table:
    // first those that become local, then the rest, each in the order of
    // their global ids.
    fn write_symbols(t: const Symtab<T>&) {
        var ok = true;
        var sum = xxh3::IdSum { on: t.hash_id, a: 0, b: 0 };
        fn put(at: i64, data: const u8[:]) -> bool {
            xxh3::add(sum, at, data);
            return ld_pwrite(t.out, at, data);
        }
        for kind in [EMIT_LOCAL, EMIT_GLOBAL] {
            var table: u8[>..] = [];
            var strs: u8[>..] = [];
            var str_at = if kind == EMIT_LOCAL { t.local_str } else { t.global_str };
            for i in order {
                let s = syms[i];
                if emitted(s) != kind { continue; }
                let v = t.values[place_of[i]];
                // GNU's unique binding is kept; a symbol the linker defines is global.
                let bind: u8 = if kind == EMIT_LOCAL { 0 } else if !s.defined || s.def_kind == WEAK { 2 }
                               else if s.def_bind == 10 { 10 } else { 1 };
                elf_symbol(table, (str_at + strs.len) as! u32, bind << 4 | v.stype, (s.def_other & ~3) | s.vis, v.shndx, v.value,
                           if s.defined { s.def_size } else { 0 });
                strs.append(names[s.name_at..s.name_at + s.name_len]);
                strs.push(0);
            }
            let index = if kind == EMIT_LOCAL { t.local_index } else { t.global_index };
            ok = ok && put(t.symtab_at + 24 * index, table) && put(t.strtab_at + str_at, strs);
        }
        // The dynamic symbol table's entries, each at the index main gave it.
        var entry: u8[>..] = [];
        for i in order {
            let v = t.values[place_of[i]];
            if v.dyn_index == 0 { continue; }
            let s = syms[i];
            // A copy (CMD_COPY) is the executable's, bound as its library binds it.
            let imported = (!s.defined || s.def_kind == SHARED) && !s.copied;
            let bind: u8 = if imported { if s.strong_ref { 1 } else { 2 } }
                           else if s.copied { if s.def_bind == 2 { 2 } else { 1 } }
                           else if s.def_kind == WEAK { 2 } else if s.def_bind == 10 { 10 } else { 1 };
            entry.clear();
            elf_symbol(entry, v.dyn_name, bind << 4 | v.stype, (s.def_other & ~3) | s.vis, if imported { 0 } else { v.shndx },
                       if imported { 0 } else { v.value }, if imported || !s.defined { 0 } else { s.def_size });
            let name = names[s.name_at..s.name_at + s.name_len];
            let version: u8[2] = [v.version as! u8, (v.version >> 8) as! u8];
            ok = ok && put(t.dynsym_at + 24 * v.dyn_index as! i64, entry) &&
                 put(t.dynstr_at + v.dyn_name as! i64, name) &&
                 put(t.versym_at + 2 * v.dyn_index as! i64, version);
        }
        // The merged strings: each group's part, where main put it.
        let at = qget<MergeAt<T>>();
        var bytes: u8[>..] = [];
        var j = 0;
        for k in at.at.len / 2 {
            let g = at.at[2 * k] as! u32;
            bytes.clear();
            while j < by_offset.len && uniqs[by_offset[j]].group == g {
                let y = uniqs[by_offset[j]];
                bytes.resize(y.offset as! i64, 0);
                bytes.append(str_bytes[(y.at as! i64)..(y.at as! i64) + (y.len as! i64)]);
                j++;
            }
            ok = ok && put(at.at[2 * k + 1] as! i64, bytes);
        }
        qput(SymtabDone { shard: shard, ok: ok, ida: sum.a, idb: sum.b });
    }

    // A flush: the archive members that would define what is referenced and
    // still undefined, as GNU ld and lld take them (Flushed).
    fn on_flush() {
        var out = Flushed { shard: shard, extract: [] };
        for i in pending {
            let s .= syms[i];
            s.pending = false;
            // As GNU ld and lld take them: a member for what nothing defines,
            // and for what only a shared library later on the command line
            // does, since there the archive comes first.
            let wanted = !s.defined || (s.def_kind == SHARED && s.lazy_prio < s.def_prio);
            if wanted && s.has_lazy && !s.requested { s.requested = true; out.extract.push(s.lazy_prio); }
        }
        pending.clear();
        qput(out);
    }
    // Once the rounds are done: counts, errors, and what the shard's part of
    // the symbol table takes (Final).
    fn on_finish() {
        var out = Final { shard: shard, symbols: 0, defined: 0, undefined: 0, duplicates: 0, shlib_undefined: 0,
                          digest: 0, locals: 0, local_strs: 0, globals: 0, global_strs: 0, names: [] };
        for &s in syms { if exported(s) { out.symbols++; } }
        for s in syms {
            let e = emitted(s);
            if e == EMIT_LOCAL { out.locals++; out.local_strs += s.name_len + 1; }
            if e == EMIT_GLOBAL { out.globals++; out.global_strs += s.name_len + 1; }
            if s.defined {
                out.defined++;
                out.digest ^= hash(s.hash ^ s.def_prio ^ (s.def_sym as u64) << 20 ^ (s.def_kind as u64) << 56);
            } else if s.strong_ref {
                out.undefined++;
                if out.names.len < 4096 { format(out.names, "U ", names[s.name_at..s.name_at + s.name_len], "\n"); }
            }
            if s.shlib_ref && !s.def_any && !(s.defined && s.def_kind != GROUP &&
                                              (s.def_kind == SHARED || s.vis == 0 || s.vis == 3)) {
                out.shlib_undefined++;
                if out.names.len < 4096 {
                    format(out.names, "S ", names[s.name_at..s.name_at + s.name_len], " ", prio_file(s.shlib_prio), "\n");
                }
            }
            if s.duplicate {
                out.duplicates++;
                if out.names.len < 4096 { format(out.names, "D ", names[s.name_at..s.name_at + s.name_len], "\n"); }
            }
        }
        qput(out);
    }
    // The shared libraries' data objects a direct reference needs copied.
    fn on_copy_keys() {
        var out = CopyKeys { shard: shard, keys: [] };
        for &s in syms {
            if s.defined && s.def_kind == SHARED && s.def_stype == 1 && s.need & reloc::NEED_COPY != 0 && s.referenced {
                out.keys.push(s.def_prio);
                out.keys.push(s.def_value);
            }
        }
        qput(out);
    }
    // Every symbol a shared library defines at an address copied, the
    // aliases of what was asked for included, is copied: defined, and
    // exported, by the executable.
    fn on_copy(pairs: const Entry[:]) {
        var copied = dictionary<u64, bool> {};
        for e in pairs { insert(copied, copy_key(e.prio, e.value), true); }
        for &s in syms {
            if s.defined && s.def_kind == SHARED && contains(copied, copy_key(s.def_prio, s.def_value)) { s.copied = true; }
        }
    }
    // Export, base the global id of the shard's first symbol: number the
    // symbols in canonical order and send their definitions, the losing
    // COMDAT groups and every occurrence's id; then merge the strings and,
    // given the values, write the shard's part of the symbol tables.
    fn on_export(base: i64) {
        for &s, i in syms { if exported(s) { order.push(i as! u32); } }
        sort(order) { a, b => before(syms[a], syms[b], names) };
        place_of.resize(syms.len, 0xffffffff);
        for i, j in order { place_of[i] = j as! u32; }
        var defs = Defs { shard: shard, defs: [] };
        for i in order {
            let y = syms[i];
            defs.defs.push(Def { prio: y.def_prio, value: y.def_value, size: y.def_size, sym: y.def_sym,
                                 shndx: y.def_shndx, kind: y.def_kind, stype: y.def_stype, need: y.need,
                                 defined: y.defined, vis: y.vis, bind: y.def_bind, referenced: y.referenced,
                                 strong: y.strong_ref, in_dso: y.in_dso,
                                 gnu_hash: gnu_hash(names[y.name_at..y.name_at + y.name_len]),
                                 name_len: y.name_len, copied: y.copied });
        }
        qput(defs);
        var losers = Losers { shard: shard, groups: [] };
        for o in occs {
            if o.sym & GROUP_MARK != 0 && syms[o.id].def_prio != o.prio { losers.groups.push(o); }
        }
        qput(losers);
        var out = Occs { shard: shard, occs: [] };
        for o in occs {
            if o.sym & GROUP_MARK == 0 { out.occs.push(Occ { prio: o.prio, sym: o.sym, id: place_of[o.id] + base as! u32 }); }
        }
        qput(out);
        merge_strings(qget<Merge<T>>().count);
        let t = qget<Symtab<T>>();
        write_symbols(t);
    }

    // The protocol: each round, symbols, then a flush; once the rounds are
    // done, finish; then export, after which the shard ends.
    loop {
        let m = qget<ToShard<T>>();
        if m.cmd == CMD_SYMBOLS { for e in m.entries { add(e); } }
        else if m.cmd == CMD_FLUSH { on_flush(); }
        else if m.cmd == CMD_COPY_KEYS { on_copy_keys(); }
        else if m.cmd == CMD_COPY { on_copy(m.entries); }
        else if m.cmd == CMD_EXPORT { on_export(m.arg); return; }
        else { on_finish(); }                                 // CMD_FINISH
    }
}

thread_fn shard_worker(shard: i64) {
    const for <C> in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16] {
        if shard == C - 1 { shard_loop([0 as u8; C], shard); }
    }
}

// Sends cmd with arg to shard k.
fn command(k: i64, cmd: u8, arg: i64) {
    const for <C> in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16] {
        if C - 1 == k { qput(ToShard<u8[C]> { cmd: cmd, arg: arg, entries: [] }); }
    }
}

// A copied object's library and address as one key: a library's prio is
// its file's number alone, and an address in it below 2^48.
fn copy_key(prio: u64, value: u64) -> u64 { value << 16 ^ (prio_file(prio) as! u64) }

// Sends CMD_COPY with the copied objects, prio and value in pairs, to each
// of n shards.
fn send_copies(pairs: const u64[:], n: i64) {
    const for <C> in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16] {
        if C <= n {
            var b = ToShard<u8[C]> { cmd: CMD_COPY, arg: 0, entries: [] };
            var i = 0;
            while i + 1 < pairs.len {
                b.entries.push(Entry { hash: 0, prio: pairs[i], size: 0, value: pairs[i + 1], sym: 0, shndx: 0, kind: 0,
                                       stype: 0, bind: 0, other: 0, need: 0, name: "" });
                i += 2;
            }
            qput(b);
        }
    }
}

// Sends cmd, with no symbols, to each of n shards.
fn broadcast(cmd: u8, n: i64) {
    const for <C> in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16] {
        if C <= n { qput(ToShard<u8[C]> { cmd: cmd, arg: 0, entries: [] }); }
    }
}

// One symbol on its way to a shard: a view of its name in the job's buffer.
struct Rec { hash: u64, prio: u64, size: u64, value: u64, sym: u32, shndx: u32, kind: u8, stype: u8, bind: u8,
             other: u8, need: u8, name: const u8[:] }

// Sends each of n shards its records, one message apiece: the records'
// indexes sorted by shard first, so that each batch is one run of them.
fn send(recs: const Rec[:], n: i64) {
    var start: i64[MAX_SHARDS + 1] = [0; MAX_SHARDS + 1];
    for r in recs { start[shard_of(r.hash, n) + 1]++; }
    for k in n { start[k + 1] += start[k]; }
    var fill = start;
    var by_shard: u32[>..] = [];
    by_shard.resize(recs.len, 0);
    for r, i in recs {
        let k = shard_of(r.hash, n);
        by_shard[fill[k]] = i as! u32;
        fill[k]++;
    }
    const for <C> in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16] {
        if C > n { return; }
        if start[C] > start[C - 1] {
            var b = ToShard<u8[C]> { cmd: CMD_SYMBOLS, arg: 0, entries: [] };
            for j in start[C - 1]..start[C] {
                let r = recs[by_shard[j]];
                b.entries.push(Entry { hash: r.hash, prio: r.prio, size: r.size, value: r.value, sym: r.sym,
                                       shndx: r.shndx, kind: r.kind, stype: r.stype, bind: r.bind, other: r.other,
                                       need: r.need, name: r.name });
            }
            qput(b);
        }
    }
}

// The global symbols of an object, as records.
fn summarize(recs: Rec[>..]&, o: const elf::Object&, p: u64) {
    let ns = elf::nsections(o);
    // Sections in a group; a symbol defined in one may be defined again.
    var grouped: bool[>..] = [];
    for g in 1..ns {
        let s = elf::section(o, g);
        if s.kind != elf::SHT_GROUP { continue; }
        if grouped.len == 0 { grouped.resize(ns, false); }
        let words = elf::contents(o, s);
        for k in 1..words.len / 4 { grouped[elf::u32le(words, k * 4)] = true; }
    }
    let n = elf::nsymbols(o);
    for i in o.first_global..n {
        let s = elf::symbol(o, i);
        let shndx = elf::symbol_section(o, i, s);
        let weak = elf::bind(s) == 2;
        let kind = if shndx == elf::SHN_UNDEF { if weak { UNDEF_WEAK } else { UNDEF } }
                   else if shndx == elf::SHN_COMMON { COMMON }
                   else if weak { WEAK }
                   else if shndx < elf::SHN_LORESERVE && grouped.len > 0 && grouped[shndx] { COMDAT }
                   else { DEF };
        let name = elf::symbol_name(o, s);
        recs.push(Rec { hash: hash(name), prio: p, size: s.size, value: s.value, sym: i as! u32, shndx: shndx,
                        kind: kind, stype: elf::stype(s), bind: elf::bind(s), other: s.other, need: 0, name: name });
    }
}

// Sends shard k where to write its symbols, and their values.
fn send_symtab(k: i64, out: i32, symtab_at: i64, strtab_at: i64, local_index: i64, global_index: i64,
               local_str: i64, global_str: i64, dynsym_at: i64, dynstr_at: i64, versym_at: i64, hash_id: bool,
               values: const SymVal[:]) {
    const for <C> in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16] {
        if C - 1 == k {
            var m = Symtab<u8[C]> { out: out, symtab_at: symtab_at, strtab_at: strtab_at, local_index: local_index,
                                    global_index: global_index, local_str: local_str, global_str: global_str,
                                    dynsym_at: dynsym_at, dynstr_at: dynstr_at, versym_at: versym_at, hash_id: hash_id,
                                    values: [] };
            m.values.append(values);
            qput(m);
        }
    }
}

// Sends shard k how many messages of strings it was sent.
fn send_merge(k: i64, count: i64) {
    const for <C> in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16] {
        if C - 1 == k { qput(Merge<u8[C]> { count: count }); }
    }
}

// Sends shard k where its part of each merge group goes in the file: group
// and offset pairs, in the order of the groups.
fn send_merge_at(k: i64, at: const u64[:]) {
    const for <C> in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16] {
        if C - 1 == k {
            var m = MergeAt<u8[C]> { at: [] };
            m.at.append(at);
            qput(m);
        }
    }
}

// Sends each of n shards the strings of the object prio whose hashes pick
// it; a bit in the result for each shard sent a message.
fn send_strings(prio: u64, recs: const StrRec[:], n: i64) -> u32 {
    var mask: u32 = 0;
    var start: i64[MAX_SHARDS + 1] = [0; MAX_SHARDS + 1];       // by shard, as send sorts symbols
    for r in recs { start[shard_of(r.hash, n) + 1]++; }
    for k in n { start[k + 1] += start[k]; }
    var fill = start;
    var by_shard: u32[>..] = [];
    by_shard.resize(recs.len, 0);
    for r, i in recs {
        let k = shard_of(r.hash, n);
        by_shard[fill[k]] = i as! u32;
        fill[k]++;
    }
    var head: u8[20] = [0; 20];
    const for <C> in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16] {
        if C > n { return mask; }
        if start[C] > start[C - 1] {
            var m = Strings<u8[C]> { prio: prio, data: [] };
            for j in start[C - 1]..start[C] {
                let r .= recs[by_shard[j]];
                put32(head, 0, r.group);
                put32(head, 4, r.index);
                put32(head, 8, r.bytes.len as! u32);
                put32(head, 12, (r.hash & 0xffffffff) as! u32);
                put32(head, 16, (r.hash >> 32) as! u32);
                m.data.append(head[..]);
                m.data.append(r.bytes);
            }
            mask |= (1 as u32) << (C - 1);
            qput(m);
        }
    }
    return mask;
}

inline fn put32(b: u8[20]&, at: i64, v: u32) {
    b[at] = (v & 0xff) as! u8;
    b[at + 1] = ((v >> 8) & 0xff) as! u8;
    b[at + 2] = ((v >> 16) & 0xff) as! u8;
    b[at + 3] = (v >> 24) as! u8;
}
