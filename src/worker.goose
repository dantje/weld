// What a worker does with a job (protocol.goose): reads an object's,
// archive members' or shared library's symbols and sends them to the
// shards; describes each object's sections for main's layout; relocates an
// object into the output; or faults in a range of the output. Workers own
// their memory: each reads into one buffer of its own, which it reuses.
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

// The section of local symbol i if it goes in the output's symbol table,
// 0 for a file symbol or an absolute one, -1 if it does not go there:
// section symbols and the assembler's .L labels.
fn local_symbol(o: const elf::Object&, i: i64) -> i64 {
    let s = elf::symbol(o, i);
    let t = elf::stype(s);
    if t == 3 || s.name == 0 || starts_with(elf::symbol_name(o, s), ".L") { return -1; }
    if t == 4 { return 0; }
    let shndx = elf::symbol_section(o, i, s);
    if shndx == elf::SHN_ABS { return 0; }
    if shndx == elf::SHN_UNDEF || shndx >= elf::SHN_LORESERVE { return -1; }
    return shndx;
}

// The strings of its sections to merge go to strs, for the shards.
fn describe(o: const elf::Object&, p: u64, offset: i64, size: i64, strs: resolve::StrRec[>..]&) -> ObjInfo {
    var info = ObjInfo { prio: p, offset: offset, size: size, first_global: o.first_global,
                         nsyms: elf::nsymbols(o), abs_locals: 0, abs_strs: 0, features: 0, isa: 0, tlsld: false,
                         merge_mask: 0, pieces: 0, merge_bytes: 0, eh: -1, abs64: 0, locals: 0, local_strs: 0, fdes: 0,
                         secs: [] };
    var mgroups: u32[>..] = [];
    var mrange: i64[>..] = [];
    var starts: u64[>..] = [];
    merging(o, mgroups, mrange, starts);
    var group: u32[>..] = [];
    group.resize(elf::nsections(o), 0);
    for g in 1..elf::nsections(o) {
        let s = elf::section(o, g);
        if s.kind != elf::SHT_GROUP { continue; }
        let words = elf::contents(o, s);
        for k in 1..words.len / 4 { group[elf::u32le(words, k * 4)] = g as! u32; }
    }
    let ns = elf::nsections(o);
    var fdes_in: u32[>..] = [];          // each section's FDEs, of an .eh_frame or of code in it
    fdes_in.resize(ns, 0);
    for i in ns {
        let s = elf::section(o, i);
        let name = elf::section_name(o, s);
        let class = if i == 0 { layout::DISCARD } else { layout::classify(name, s) };
        let named = class != layout::DISCARD && is_c_identifier(name);
        let key = if named { hash(name) }
                  else if class == layout::INIT_ARRAY || class == layout::FINI_ARRAY { array_priority(name) }
                  else if class == layout::NONALLOC { layout::nonalloc_key(name) }
                  else { 0 };
        if class == layout::EH_FRAME { fdes_in[i] = eh::count_fdes(elf::contents(o, s)) as! u32; }
        // A section of strings to merge takes no room of its own: its
        // strings go to the shards, and its merge group is laid out whole.
        let mg = mgroups[i];
        if mg != 0 {
            let b = elf::contents(o, s);
            let lo = mrange[2 * i];
            let hi = mrange[2 * i + 1];
            let palign = merge::align_of(mg) as! i64;
            info.merge_bytes += b.len + (hi - lo) * (palign - 1) + palign;
            for k in lo..hi {
                let end = if k + 1 < hi { starts[k + 1] as! i64 } else { b.len };
                let piece = b[(starts[k] as! i64)..end];
                strs.push(resolve::StrRec { group: mg, index: k as! u32, hash: xxh3::hash(piece), bytes: piece });
            }
        }
        // .eh_frame's records follow one another 4-byte aligned, and no
        // padding may come between them, where a zero would end the table:
        // its sections are only as aligned, sizes left out of them or not.
        let align = if mg != 0 { 1 } else if class == layout::EH_FRAME { min(4, max(1, s.align)) } else { max(1, s.align) };
        info.secs.push(Sec { class: class, named: named, align2: log2(align), group: group[i],
                             key: if s.kind == elf::SHT_GROUP { 0 } else { key },
                             size: if mg != 0 || s.kind == elf::SHT_GROUP { 0 } else { s.size }, addr: 0 });
        if s.kind == layout::SHT_NOTE && name == ".note.gnu.property" {
            let f, isa = properties(elf::contents(o, s));
            info.features = f;
            info.isa = isa;
        }
    }
    // Each section's absolute 64-bit relocations, local symbols and FDEs,
    // summed for the object and for each COMDAT group.
    var abs64: u32[>..] = [];
    abs64.resize(ns, 0);
    for i in 1..ns {
        let s = elf::section(o, i);
        if s.kind != elf::SHT_RELA { continue; }
        let table = elf::contents(o, s);
        let alloc = info.secs[s.info].class != layout::DISCARD && info.secs[s.info].class != layout::NONALLOC;
        for k in elf::nrelas(s) {
            let kind = elf::u32le(table[k * elf::RELA_SIZE + 8..k * elf::RELA_SIZE + 12], 0);
            if kind == reloc::R_X86_64_64 && alloc { abs64[s.info]++; }
            if kind == reloc::R_X86_64_TLSLD { info.tlsld = true; }
        }
    }
    var locals: u32[>..] = [];
    var local_strs: u32[>..] = [];
    locals.resize(ns, 0);
    local_strs.resize(ns, 0);
    for i in 1..o.first_global {
        let k = local_symbol(o, i);
        if k < 0 { continue; }
        let n = elf::symbol_name(o, elf::symbol(o, i)).len + 1;
        if k == 0 { info.abs_locals++; info.abs_strs += n; }
        else { locals[k]++; local_strs[k] += n as! u32; }
    }
    info.pieces = starts.len;
    // Each FDE's bytes go on the section of the code it describes, so that
    // main can leave them out with it; those of code left out already
    // come off the .eh_frame here. Relocating takes the same (eh_records).
    var eh_bytes: u32[>..] = [];
    eh_bytes.resize(ns, 0);
    var recs: i64[>..] = [];
    let eh, rela = eh_records(o, recs);
    if eh > 0 {
        info.eh = eh;
        for j in recs.len / 3 {
            let t = fde_section(o, rela, recs[3 * j + 2]);
            if t == 0 || t == eh || info.secs[t].class == layout::EH_FRAME { continue; }
            let len = recs[3 * j + 1] as! u32;
            if info.secs[t].class == layout::DISCARD {
                info.secs[eh].size -= len;
                fdes_in[eh]--;
            } else {
                eh_bytes[t] += len;
                fdes_in[t]++;
                fdes_in[eh]--;               // counted with the code, which may go
            }
        }
    }
    for i in 1..ns {
        let c = info.secs[i].class;
        if c == layout::DISCARD { continue; }
        info.abs64 += abs64[i];
        info.locals += locals[i];
        info.local_strs += local_strs[i];
        info.fdes += fdes_in[i];
        let g = group[i];
        if g != 0 { add_to_group(info.secs[g], abs64[i], fdes_in[i], locals[i], local_strs[i], eh_bytes[i]); }
    }
    return info;
}

// The object's .eh_frame section, if it has one, and only one, whose
// records can be read (eh::records, into recs), with its relocations; else
// 0. Its FDEs can be left out with the code they describe.
fn eh_records(o: const elf::Object&, recs: i64[>..]&) -> i64, elf::Section {
    let ns = elf::nsections(o);
    var eh = 0;
    var count = 0;
    for i in 1..ns {
        let s = elf::section(o, i);
        if s.flags & layout::SHF_ALLOC == 0 || (s.kind != layout::SHT_X86_64_UNWIND && s.kind != 1) { continue; }
        let name = elf::section_name(o, s);
        if (s.kind == layout::SHT_X86_64_UNWIND || name == ".eh_frame") && layout::classify(name, s) == layout::EH_FRAME {
            eh = i;
            count++;
        }
    }
    var rela = elf::section(o, 0);
    var nrela = 0;
    if count != 1 { return 0, rela; }
    for g in 1..ns {                     // nor in a COMDAT group, whose FDEs go with it
        let s = elf::section(o, g);
        if s.kind != elf::SHT_GROUP { continue; }
        let words = elf::contents(o, s);
        for k in 1..words.len / 4 { if elf::u32le(words, k * 4) == eh as! u32 { return 0, rela; } }
    }
    for i in 1..ns {
        let s = elf::section(o, i);
        if s.kind == elf::SHT_RELA && s.info == eh as! u32 { rela = s; nrela = elf::nrelas(s); }
    }
    if !eh::records(o, elf::contents(o, elf::section(o, eh)), rela, nrela, recs) { return 0, rela; }
    return eh, rela;
}

// The section of the code the FDE whose start relocation k (-1 if none) in
// rela describes, if a local symbol names it: else 0.
fn fde_section(o: const elf::Object&, rela: elf::Section, k: i64) -> i64 {
    if k < 0 { return 0; }
    let r = elf::rela(o, rela, k);
    if r.sym <= 0 || r.sym >= o.first_global { return 0; }
    let t = elf::symbol_section(o, r.sym, elf::symbol(o, r.sym)) as! i64;
    return if t > 0 && t < elf::nsections(o) { t } else { 0 };
}

// Which of an object's sections merge their strings (merge.goose): each
// section's merge group in groups, 0 if none; the start of each of their
// strings in starts, section after section, and each section's first and
// end there in range, two a section. Describing an object and relocating
// it take the same.
fn merging(o: const elf::Object&, groups: u32[>..]&, range: i64[>..]&, starts: u64[>..]&) {
    let ns = elf::nsections(o);
    var relocated: bool[>..] = [];
    var global: bool[>..] = [];
    merge::section_facts(o, relocated, global);
    var grouped: bool[>..] = [];
    grouped.resize(ns, false);
    for g in 1..ns {
        let s = elf::section(o, g);
        if s.kind != elf::SHT_GROUP { continue; }
        let words = elf::contents(o, s);
        for k in 1..words.len / 4 {
            let m = elf::u32le(words, k * 4);
            if m < ns as! u32 { grouped[m] = true; }
        }
    }
    groups.resize(ns, 0);
    range.resize(2 * ns, 0);
    for i in 1..ns {
        let s = elf::section(o, i);
        range[2 * i] = starts.len;
        range[2 * i + 1] = starts.len;
        if s.flags & merge::SHF_MERGE == 0 { continue; }
        let name = elf::section_name(o, s);
        let class = layout::classify(name, s);
        if is_c_identifier(name) { continue; }       // __start_ and __stop_ can name it
        let key = if class == layout::NONALLOC { layout::nonalloc_key(name) } else { 0 };
        let g = merge::group_of(s, class, key, grouped[i], relocated[i], global[i]);
        if g == 0 || !merge::split(elf::contents(o, s), g, starts) { continue; }
        groups[i] = g;
        range[2 * i + 1] = starts.len;
    }
}

fn is_c_identifier(name: const u8[:]) -> bool {
    if name.len == 0 || (name[0] >= '0' && name[0] <= '9') { return false; }
    for c in name {
        if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') { return false; }
    }
    return true;
}

// .init_array.N and .fini_array.N run in order of N; plain .init_array last.
fn array_priority(name: const u8[:]) -> u64 {
    let dot = find(name[1..], ".");
    if dot < 0 { return 65536; }
    let n, ok = parse_int(name[dot + 2..]);
    return if ok && n >= 0 && n < 65536 { n as! u64 } else { 65536 };
}

let GRP_COMDAT: u32 = 1;

// The signature of COMDAT group g: its symbol's name, or for a section
// symbol, the section's.
fn signature(o: const elf::Object&, g: elf::Section) -> const u8[:] {
    let s = elf::symbol(o, g.info);
    if elf::stype(s) == 3 { return elf::section_name(o, elf::section(o, elf::symbol_section(o, g.info, s))); }
    return elf::symbol_name(o, s);
}

// Marks the global symbols whose relocations need a GOT slot, and adds the
// __start_ and __stop_ symbols a section name defines and the COMDAT
// groups the object has, their names in names. A group's name is its
// signature after a \x01, which no symbol's name has.
// The object's global symbols are recs[base..], in order.
fn needs(recs: resolve::Rec[>..]&, base: i64, names: u8[>..]&, o: const elf::Object&, p: u64) {
    let ns = elf::nsections(o);
    for i in 1..ns {
        let s = elf::section(o, i);
        if s.kind == elf::SHT_RELA {
            let target = elf::section(o, s.info);
            if target.flags & layout::SHF_ALLOC == 0 { continue; }
            let b = elf::contents(o, target);
            let table = elf::contents(o, s);
            for k in elf::nrelas(s) {
                // Only the type, until it is one that can need a slot.
                let kind = elf::u32le(table[k * elf::RELA_SIZE + 8..k * elf::RELA_SIZE + 12], 0);
                if !reloc::may_need_got(kind) { continue; }
                let r = elf::rela(o, s, k);
                if r.sym < o.first_global || r.sym >= elf::nsymbols(o) { continue; }
                let need = reloc::got_need(r.kind, b, r.offset as! i64);
                if need != 0 { recs[base + r.sym - o.first_global].need |= need; }
            }
        } else if s.kind == elf::SHT_GROUP && elf::u32le(elf::contents(o, s), 0) & GRP_COMDAT != 0 {
            let at = names.len;
            names.push(1);
            names.append(signature(o, s));
            let name = names[at..];
            recs.push(resolve::Rec { hash: hash(name), prio: p, size: 0, value: 0, sym: i as! u32 | resolve::GROUP_MARK,
                                     shndx: 0, kind: resolve::GROUP, stype: 0, bind: 0, other: 0, need: 0, name: name });
        } else if s.flags & layout::SHF_ALLOC != 0 && is_c_identifier(elf::section_name(o, s)) {
            let name = elf::section_name(o, s);
            for start in [true, false] {
                let at = names.len;
                format(names, if start { "__start_" } else { "__stop_" }, name);
                let full = names[at..];
                recs.push(resolve::Rec { hash: hash(full), prio: p, size: 0, value: 0, sym: 0, shndx: i as! u32,
                                         kind: if start { resolve::START } else { resolve::STOP }, stype: 0, bind: 0, other: 0, need: 0,
                                         name: full });
            }
        }
    }
}

// Reads an object's symbols into recs, their generated names into names;
// false if it is not one.
fn read_object(job: const Job&, data: const u8[:], p: u64, recs: resolve::Rec[>..]&, names: u8[>..]&) -> bool {
    let o, err = elf::open(data);
    if err.len > 0 {
        if job.kind == JOB_MEMBER { print(job.path, "(member at ", resolve::prio_offset(p), "): ", err); }
        else { print(job.path, ": ", err); }
        return false;
    }
    let base = recs.len;
    resolve::summarize(recs, o, p);
    needs(recs, base, names, o, p);
    return true;
}

// Hides the definitions among recs, an excluded archive's member's: they
// are not exported, and where they are defined as well, the most hidden
// visibility wins as ever. References keep theirs.
fn hide(recs: resolve::Rec[:]) {
    for &r in recs {
        if r.kind == resolve::DEF || r.kind == resolve::WEAK || r.kind == resolve::COMMON || r.kind == resolve::COMDAT {
            if r.other & 3 == 0 || r.other & 3 == 3 { r.other = (r.other & ~3) | 2; }     // STV_HIDDEN
        }
    }
}

// An object read, to describe once its job is done: its bytes in the job's
// buffer, and where it is in its file.
struct Read { start: i64, len: i64, prio: u64, offset: i64 }

// Runs a job, sending its results: for objects, their symbols to the
// shards, then JobDone, then their descriptions to main, which needs them
// only after the last round, so they keep no round waiting.
fn run_job(job: const Job&, buf: u8[>..]&) {
    var done = JobDone { errors: 0, objects: 0, dsos: 0, ida: 0, idb: 0 };
    var dsos_sent = 0;
    var reads: Read[>..] = [];
    if job.kind == JOB_MEMBER {
        // The members whose headers are at the offsets in data, read one
        // after another into buf, which views of earlier ones survive; then
        // one message to each shard for all of them.
        var hdr: u8[>..] = [];
        var names: u8[>..] = [];
        var recs: resolve::Rec[>..] = [];
        for at in job.data {
            let pos = at as! i64;
            hdr.clear();
            guard ld_pread(job.fd, pos, ar::HDR_SIZE, hdr) else { print(job.path, ": cannot read member at ", pos); done.errors++; continue; }
            let raw, size, ok = ar::parse_header(hdr);
            guard ok else { print(job.path, ": bad member header at ", pos); done.errors++; continue; }
            var skip = 0;                    // a BSD name opens the body
            if starts_with(raw, "#1/") {
                let n, named = ar::decimal(raw[3..]);
                guard named && n <= size else { print(job.path, ": bad member name at ", pos); done.errors++; continue; }
                skip = n;
            }
            let start = buf.len;
            guard ld_pread(job.fd, pos + ar::HDR_SIZE + skip, size - skip, buf) else {
                print(job.path, ": cannot read member at ", pos);
                done.errors++;
                continue;
            }
            let p = resolve::prio(job.file, pos);
            let first = recs.len;
            if read_object(job, buf[start..], p, recs, names) {
                if job.hide { hide(recs[first..]); }
                reads.push(Read { start: start, len: buf.len - start, prio: p, offset: pos + ar::HDR_SIZE + skip });
            } else {
                done.errors++;
            }
        }
        resolve::send(recs, job.shards);
    } else if job.kind == JOB_RELOCATE {
        var fdes = Fdes { pairs: [] };
        if !ld_pread(job.fd, job.offset, job.size, buf) { print("cannot read ", job.path); done.errors++; }
        else {
            var sum = xxh3::IdSum { on: job.hash_id, a: 0, b: 0 };
            done.errors = relocate(job, buf, job.data, fdes.pairs, sum);
            done.ida = sum.a;
            done.idb = sum.b;
        }
        if job.fdes { qput(fdes); }                 // main waits for one from each job that was asked
    } else if job.kind == JOB_SHARED {
        // Not read whole: only what it defines (dso.goose).
        var t = dso::Tables { dynsym_at: 0, dynsym_len: 0, dynstr_at: 0, dynstr_len: 0, versym_at: 0, versym_len: 0,
                              verdef_at: 0, verdef_len: 0, soname_at: 0, soname_len: 0, dynamic_at: 0, dynamic_len: 0 };
        let err = dso::read_tables(job.fd, job.size, buf, t);
        if err.len > 0 { print(job.path, ": ", err); done.errors++; }
        else {
            var recs: resolve::Rec[>..] = [];
            let p = resolve::prio(job.file, 0);
            // An indirect library's definitions say only, as its references,
            // what the executable exports, and what a given library may use:
            // they define nothing for the link, where an object may not use
            // a library not given.
            dso::each_definition(buf, t) { i, sym, name, version =>
                recs.push(resolve::Rec { hash: hash(name), prio: p, size: sym.size, value: sym.value, sym: i as! u32,
                                         shndx: version, kind: if job.indirect { resolve::INDIRECT_DEF } else { resolve::SHARED },
                                         stype: elf::stype(sym), bind: elf::bind(sym), other: sym.other, need: 0,
                                         name: name });
            };
            // What it uses, which a PIE exports if it defines and the link
            // must define if it checks (--no-allow-shlib-undefined).
            if job.refs {
                dso::each_reference(buf, t) { name, bind =>
                    recs.push(resolve::Rec { hash: hash(name), prio: p, size: 0, value: 0, sym: 0, shndx: 0,
                                             kind: if job.indirect { resolve::INDIRECT } else { resolve::DSO_REF }, stype: 0,
                                             bind: bind, other: 0, need: 0, name: name });
                };
                dso::each_hidden_definition(buf, t) { name =>
                    recs.push(resolve::Rec { hash: hash(name), prio: p, size: 0, value: 0, sym: 0, shndx: 0,
                                             kind: resolve::SHLIB_DEF, stype: 0, bind: 0, other: 0, need: 0, name: name });
                };
            }
            resolve::send(recs, job.shards);
            var info = DsoInfo { prio: if job.indirect { job.aux as! u64 } else { p }, indirect: job.indirect, soname: "",
                                 ver_len: 0, needed_len: 0, text: [] };
            if t.soname_len > 0 && t.soname_len < 256 { info.soname = buf[t.soname_at..t.soname_at + t.soname_len]; }
            else {                               // no DT_SONAME: the file's name
                var k = job.path.len - 1;
                while k >= 0 && job.path[k] != '/' { k--; }
                info.soname = job.path[k + 1..];
            }
            dso::each_version(buf, t) { index, name =>
                info.text.push(index as! u8); info.text.push((index >> 8) as! u8);
                info.text.append(name); info.text.push(0);
            };
            info.ver_len = info.text.len;
            if job.refs {
                dso::each_dynamic_string(buf, t, dso::DT_NEEDED) { name => info.text.append(name); info.text.push(0); };
                info.needed_len = info.text.len - info.ver_len;
                var runpath = false;
                dso::each_dynamic_string(buf, t, dso::DT_RUNPATH) { dirs => info.text.append(dirs); runpath = true; };
                if !runpath { dso::each_dynamic_string(buf, t, dso::DT_RPATH) { dirs => info.text.append(dirs); }; }
            }
            dsos_sent = 1;
            qput(info);
        }
    } else if job.kind == JOB_POPULATE {
        ld_populate(job.offset, job.size);
    } else if !ld_pread(job.fd, job.offset, job.size, buf) {
        print("cannot read ", job.path);
        done.errors++;
    } else if job.kind == JOB_INDEX {
        var recs: resolve::Rec[>..] = [];
        let ok = ar::each_index_entry(buf, job.aux) { name, at =>
            recs.push(resolve::Rec { hash: hash(name), prio: resolve::prio(job.file, at), size: 0, value: 0, sym: 0,
                                     shndx: 0, kind: resolve::LAZY, stype: 0, bind: 0, other: 0, need: 0, name: name });
        };
        if ok { resolve::send(recs, job.shards); } else { print(job.path, ": bad symbol index"); done.errors++; }
    } else {
        var names: u8[>..] = [];
        var recs: resolve::Rec[>..] = [];
        let p = resolve::prio(job.file, 0);
        if read_object(job, buf, p, recs, names) {
            resolve::send(recs, job.shards);
            reads.push(Read { start: 0, len: buf.len, prio: p, offset: 0 });
        } else {
            done.errors++;
        }
    }
    done.objects = reads.len;
    done.dsos = dsos_sent;
    qput(done);
    for r in reads {
        let o = elf::open_unchecked(buf[r.start..r.start + r.len]);
        var strs: resolve::StrRec[>..] = [];
        var info = describe(o, r.prio, r.offset, r.len, strs);
        if strs.len > 0 { info.merge_mask = resolve::send_strings(r.prio, strs, job.shards); }
        qput(info);
    }
}

// Relocates the object in buf and writes its sections, and its local
// symbols, to the output: where they go is the job's at, and data holds
// its tables as RelocAt says (protocol.goose).
fn relocate(job: const Job&, buf: u8[>..]&, data: const u64[:], fde_pairs: u64[>..]&, sum: xxh3::IdSum&) -> i64 {
    let o, err = elf::open(buf);
    if err.len > 0 { print(job.path, ": ", err); return 1; }
    let ns = elf::nsections(o);
    let ng = elf::nsymbols(o) - o.first_global;
    let at = job.at;
    let columns = if job.shared { 3 } else { 2 };        // imports, slots and with dynamic tables dynx
    let ndeltas = at.ndeltas;
    let npieces = at.npieces;
    guard data.len == ns + columns * ng + ndeltas + npieces else { print(job.path, ": changed while linking"); return 1; }
    let deltas = data[ns + columns * ng..ns + columns * ng + ndeltas];
    let maddr = data[ns + columns * ng + ndeltas..];
    var mgroups: u32[>..] = [];          // its sections of merged strings, and where the strings went
    var mrange: i64[>..] = [];
    var mstart: u64[>..] = [];
    merging(o, mgroups, mrange, mstart);
    guard maddr.len == npieces && mstart.len == npieces else { print(job.path, ": changed while linking"); return 1; }
    var msec: u32[>..] = [];             // each local symbol's section, if one of merged strings
    if npieces > 0 {
        msec.resize(o.first_global, 0);
        for i in 1..o.first_global {
            let k = elf::symbol_section(o, i, elf::symbol(o, i));
            if k > 0 && k < ns as! u32 && mgroups[k] != 0 { msec[i] = k; }
        }
    }
    var place: u64[>..] = [];           // address and file offset, two a section, as reloc::apply takes them
    var out_index: u64[>..] = [];       // and its output section
    for i in ns {
        let v = data[i];
        if v == reloc::NOT_PLACED { place.push(v); place.push(v); out_index.push(0); continue; }
        let addr = v & 0xffffffffffff;
        let delta = deltas[(v >> 48) as! i64];
        place.push(addr);
        place.push(if delta == reloc::NOT_PLACED { delta } else { addr + delta });
        out_index.push(v >> 48);
    }
    let imports = data[ns..ns + ng];
    let packed = data[ns + ng..ns + 2 * ng];
    var gots: u64[>..] = [];
    var plts: u64[>..] = [];
    var dyns: u64[>..] = [];
    var tlsgds: u64[>..] = [];
    for g in ng {
        let got = packed[g] & 0xffffffff;
        let plt = packed[g] >> 32;
        gots.push(if got == 0 { 0 } else { at.got + 8 * (got - 1) });
        if job.shared {
            let x = data[ns + 2 * ng + g];
            let pair = (x >> 32) & 0x7fffffff;
            plts.push(if plt == 0 { 0 } else { at.plt + 16 * (plt - 1) });
            dyns.push(x & (0xffffffff | reloc::PREEMPTIBLE));
            tlsgds.push(if pair == 0 { 0 } else { at.got + 8 * (pair - 1) });
        }
    }
    var dyn: u8[>..] = [];
    var rela_for: i64[>..] = [];
    rela_for.resize(ns, 0);
    for i in 1..ns {
        let s = elf::section(o, i);
        if s.kind == elf::SHT_RELA { rela_for[s.info] = i; }
    }
    var errors = 0;
    var out: u8[>..] = [];
    var recs: i64[>..] = [];             // .eh_frame's records, if FDEs of code left out go (eh_records)
    let eh, eh_rela = eh_records(o, recs);
    for i in 1..ns {
        if place[2 * i + 1] == reloc::NOT_PLACED || mgroups[i] != 0 { continue; }    // the shards write merged strings
        let s = elf::section(o, i);
        if s.kind == elf::SHT_NOBITS { continue; }
        out.clear();
        out.append(elf::contents(o, s));
        if rela_for[i] > 0 {
            // In debugging information, a reference into a section left out
            // gets the tombstone DWARF tools skip: all ones, but one less in
            // .debug_ranges and .debug_loc, where all ones selects a base
            // address (as lld does).
            let name = elf::section_name(o, s);
            let debug = s.flags & layout::SHF_ALLOC == 0 && starts_with(name, ".debug_");
            let ctx = reloc::Context { tp: at.tp, tls_start: at.tls_start, shared: job.shared && !job.pie,
                                       dynamic: job.shared,
                                       tlsld_got: at.tlsld_got, writable: s.flags & layout::SHF_WRITE != 0,
                                       alloc: s.flags & layout::SHF_ALLOC != 0,
                                       tombstone: if !debug { 0 } else if name == ".debug_ranges" || name == ".debug_loc" {
                                           0xfffffffffffffffe } else { 0xffffffffffffffff } };
            let rela = elf::section(o, rela_for[i]);
            if i == eh {
                // The FDEs of code left out are left out: each record kept
                // is relocated as where it goes, and an FDE's pointer to
                // its CIE, the distance back to it, set anew.
                var full: u8[>..] = [];
                full.append(out);
                var moved: i64[>..] = [];        // each record's new offset, -1 if left out
                var size = 0;
                for j in recs.len / 3 {
                    let t = fde_section(o, eh_rela, recs[3 * j + 2]);
                    let gone = t > 0 && place[2 * t] == reloc::NOT_PLACED;
                    moved.push(if gone { -1 } else { size });
                    if !gone { size += recs[3 * j + 1]; }
                }
                out.clear();
                var k = 0;
                let n = elf::nrelas(rela);
                var end = 0;
                for j in recs.len / 3 {
                    let at = recs[3 * j];
                    end = at + recs[3 * j + 1];
                    let from = k;
                    while k < n && elf::rela(o, rela, k).offset < end as! u64 { k++; }
                    if moved[j] < 0 { continue; }
                    let e = reloc::apply(o, rela, from, k, full, place[2 * i] + moved[j] as! u64 - at as! u64, place, imports,
                                         gots, plts, dyns, tlsgds, ctx, dyn, msec, mrange, mstart, maddr);
                    if e.len > 0 { print(job.path, ": .eh_frame: ", e); errors++; }
                    out.append(full[at..end]);
                    let id = eh::u32at(full, at + 4) as! i64;
                    if id != 0 {                 // an FDE: its CIE's new place
                        let cie = at + 4 - id;
                        var c = 0;
                        while c < recs.len / 3 && recs[3 * c] != cie { c++; }
                        if c == recs.len / 3 || moved[c] < 0 { print(job.path, ": .eh_frame: an FDE's CIE is not a record"); errors++; }
                        else {
                            let v = (moved[j] + 4 - moved[c]) as! u64;
                            for b in 4 { out[moved[j] + 4 + b] = (v >> (8 * b as! u64)) as! u8; }
                        }
                    }
                }
                // What follows the records, the terminator if any.
                let e = reloc::apply(o, rela, k, n, full, place[2 * i] + size as! u64 - end as! u64, place, imports, gots,
                                     plts, dyns, tlsgds, ctx, dyn, msec, mrange, mstart, maddr);
                if e.len > 0 { print(job.path, ": .eh_frame: ", e); errors++; }
                out.append(full[end..]);
            } else {
                let e = reloc::apply(o, rela, 0, elf::nrelas(rela), out, place[2 * i], place, imports, gots, plts, dyns, tlsgds,
                                     ctx, dyn, msec, mrange, mstart, maddr);
                if e.len > 0 { print(job.path, ": ", elf::section_name(o, s), ": ", e); errors++; }
            }
        }
        if job.fdes && layout::classify(elf::section_name(o, s), s) == layout::EH_FRAME {
            eh::fde_starts(out, place[2 * i], fde_pairs);
        }
        if !put(job.out, place[2 * i + 1] as! i64, out, sum) { print("cannot write the output"); errors++; }
    }

    // The local symbols, in the order of the object's symbol table, those
    // of sections left out left out; describe counted the same ones.
    var table: u8[>..] = [];
    var strs: u8[>..] = [];
    for i in 1..o.first_global {
        let k = local_symbol(o, i);
        if k < 0 || (k > 0 && place[2 * k] == reloc::NOT_PLACED) { continue; }
        let s = elf::symbol(o, i);
        let shndx: u64 = if k == 0 { elf::SHN_ABS } else { out_index[k] };
        var value = if k == 0 { if elf::stype(s) == 4 { 0 } else { s.value } } else { place[2 * k] + s.value };
        if k > 0 && mgroups[k] != 0 {                    // a label in merged strings: its string's copy
            let j = merge::piece(mstart, mrange[2 * k], mrange[2 * k + 1], s.value);
            if j >= 0 { value = maddr[j] + (s.value - mstart[j]); }
        }
        if elf::stype(s) == 6 && k > 0 { value -= at.tls_start; }      // TLS: from the segment's start
        resolve::elf_symbol(table, (at.str_index + strs.len as! u64) as! u32, s.info, s.other, shndx as! u16, value, s.size);
        strs.append(elf::symbol_name(o, s));
        strs.push(0);
    }
    if job.shared {
        guard dyn.len / 24 <= at.rela_room as! i64 else { print(job.path, ": more run-time relocations than counted"); return errors + 1; }
        if !put(job.out, at.rela_at as! i64, dyn, sum) { print("cannot write the output"); return errors + 1; }
    }
    if !put(job.out, at.symtab_at as! i64, table, sum) || !put(job.out, (at.strtab_at + at.str_index) as! i64, strs, sum) {
        print("cannot write the output");
        return errors + 1;
    }
    return errors;
}

thread_fn worker() {
    var buf: u8[>..] = [];
    ld_prefer_huge(buf, 256 << 20);
    loop {
        let job = qget<Job>();
        if job.kind == JOB_STOP { break; }
        buf.clear();
        run_job(job, buf);
    }
}
