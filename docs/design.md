# How weld works

This is the map: what runs where, in what order, what crosses between
threads, and the words the code uses. The README says what weld does and how
to run it; [numbers.md](numbers.md) has the measurements behind the choices
here, the experiments that did not help included. Most of them are of one
link, called the large link below: a C++ shared library of 2,266 objects
(two of them Rust archives), with 178,532 global symbols and about 210 MB
of output, most of it debugging information.

## Principles

Goose has no heap and no shared memory between threads, so the design
follows from what it does give us:

* **Verify, then read without copying.** `elf::check` validates every
  offset, size, link and index the accessors follow, once; `elf::open`
  records where the tables are, and the accessors decode one record at a
  time at constant offsets. The compiler removes the bounds checks inside
  each decoder, and the C compiler turns the byte loads into single
  loads. Malformed input yields an error message, never an abort (fuzzed).
* **Workers own their memory; ranges cross as messages.** A worker is a
  separate program. Main opens every input once (a file descriptor is a
  plain integer valid in every thread) and splits archives into jobs of
  whole members, up to 4 MB each, by reading member headers alone. A job is
  a small flat message: `fd`, offset, size. The worker `pread`s that range
  into one buffer it reuses, so its pages are faulted in once and stay
  in cache. `io.c`, a sidecar of four functions, provides the ranged read,
  since `os.read_file` reads whole files only.
* **Results are flat values.** A worker returns what it found as one flat
  struct through a typed queue.
* **The symbol table is sharded over long-lived workers.** Queues are
  typed, not addressed, so each shard has a queue type of its own:
  `ToShard<u8[k]>`, generated with `const for` over the constants 1 to 16.
  A parse worker sends each shard one batch per job, built in place as a
  message with a growable tail of variable-size entries. Each shard owns
  its table: a grow-only name arena, entries, and open-addressed slots
  probed with the hash the parse worker computed.
* **Archive members are taken in rounds, decided at barriers.** Round one
  registers every object and every archive's symbol index (as lazy
  symbols). At each flush, every shard names the members that would define
  a symbol referenced strongly and still undefined. Main deduplicates them
  and the parse workers read them, and this repeats until a round takes
  none. Because shards decide only at a flush, the result does not depend
  on message order or on the number of shards (the digest is the same at 2
  and at 16). Unlike GNU ld, which takes members one at a time, a round
  does not take a member for a symbol that another member taken in the same
  round defines. For the static Goose compiler this means 2 fewer members
  (1,339 against 1,341), both redundant.
* **Threads cost what a megabyte of reading does.** Starting one takes
  about 50-100 µs, so the number of parse workers and shards follows from
  the input size (one per 4 MB). The shard count is decided at run time:
  symbols map to `hash × n >> 64`. Nothing waits for the workers at exit.

Reading whole files instead cost 1.5 s on the corpus below, two thirds of
it in the kernel faulting in fresh data-stack pages for a 2 GB archive
that one worker read alone.

## Threads

A link runs on three kinds of thread, which share no memory: everything
between them is a message, copied, through a queue chosen by the message's
type (Goose's typed queues).

* **Main** (`link.goose`, `run`) opens the inputs, queues jobs, collects
  what comes back, decides archive members round by round, lays the output
  out, and writes the linker's own tables. It is the serial part, and on
  large links the critical path.
* **Workers** (`worker.goose`; their messages in `protocol.goose`) take jobs from one shared queue: read an
  object's symbols, an archive's index or a batch of its members, a shared
  library's dynamic symbols; later relocate an object into the output, or
  fault in a range of it. Their number follows the input size (one per
  8 MB, two at least, at most two thirds of the hardware threads).
* **Shards** (`resolve.goose`, their rules in `symbols.goose`) each own the global symbols whose hash picks
  them, and the merged strings likewise: they resolve, decide which members
  a round takes, number their symbols, merge their strings, and finally
  write their part of the symbol tables. Their number follows the input
  size alone, so that the output does not depend on the machine.

`weld link` forks first (`io.c`, `ld_fork`): the child links, and the parent
exits once the output is complete, leaving the teardown off the caller's
clock.

## The phases

`--stats` prints a line as each step ends; these are main's steps, in order.
In `link::run`, whose comment lists them, they are grouped into seven
phases, each marked `// Phase N:` (inputs and round one, resolution, the
output made early, export and layout, the linker's own sections, headers
and the symbol table, writing).

| `--stats` line | What happens |
|---|---|
| workers, shards started; jobs queued | inputs opened, round one queued largest first |
| round 1 read | every object's symbols and every archive's index are in the shards |
| flushed: N members to take / round N read | shards name the members that define what is undefined; workers read them; until a round takes none |
| descriptions collected | each object's sections, for layout (`ObjInfo`) |
| N libraries read that the given ones need | `DT_NEEDED` followed, for a PIE or when shared libraries' symbols are checked |
| resolved | shards finish: undefined, duplicate and shared-library errors reported |
| output made | the file made at an upper bound of its size; two workers fault in what it surely takes |
| definitions received | shards number their symbols (export) and send each one's definition |
| objects indexed / group copies left out | COMDAT groups decided |
| merge groups | merged strings and constants laid out, from the shards' answers |
| sections placed / synthetic sections sized / addresses assigned | the layout |
| imports gathered / symbol table laid out / headers written | GOT, PLT, dynamic tables, ELF headers |
| places of N sections | each input section's address, for the relocation jobs |
| N jobs queued | one relocation job an object |
| symbol values sent | the shards get their symbols' values and write the symbol tables |
| relocation jobs queued / written | `.dynamic`, notes, `.eh_frame_hdr`, the build ID; then wait |

## Messages

| Message | From → to | What |
|---|---|---|
| `Job` | main → workers | one job: `kind` says which (`JOB_OBJECT`, `JOB_INDEX`, `JOB_MEMBER`, `JOB_SHARED`, `JOB_RELOCATE`, `JOB_POPULATE`, `JOB_STOP`); a relocation job's addresses in `RelocAt`, its tables in `data` |
| `JobDone` | workers → main | a job finished: errors, how many descriptions follow, its build-ID sum |
| `ObjInfo` | workers → main | an object's sections and counts, for layout |
| `DsoInfo` | workers → main | a shared library's name, versions, `DT_NEEDED` and run path |
| `Fdes` | workers → main | a relocation job's FDE addresses, for `.eh_frame_hdr` |
| `ToShard<u8[k]>` | workers, main → shard k | symbol occurrences (`Entry`), or a command (`CMD_FLUSH`, `CMD_COPY_KEYS`, `CMD_COPY`, `CMD_FINISH`, `CMD_EXPORT`) |
| `Strings<u8[k]>` | workers → shard k | an object's strings to merge whose hash picks shard k |
| `Flushed` | shards → main | the archive members a round takes |
| `CopyKeys` | shards → main | for a PIE: the shared libraries' data a direct reference needs copied |
| `Final` | shards → main | counts and errors after the last round |
| `Defs`, `Occs`, `Losers` | shards → main | after export: each symbol's definition, each occurrence's symbol id, the COMDAT groups that lost |
| `Merge<u8[k]>`, `MergeDone`, `MergeAt<u8[k]>` | main ↔ shards | merging strings: how many to expect, the shard's parts, where they go |
| `Symtab<u8[k]>`, `SymtabDone` | main ↔ shards | the symbols' values; the shard has written its part |

Per-shard types (`ToShard<u8[k]>` and the like) give each shard a queue of
its own: queues are chosen by type, not addressed. `const for` over 1 to 16
generates them.

## Words

| Word | Meaning |
|---|---|
| prio | an object's place in command-line order, as one number: the input's index << 40, plus a member's offset in its archive. Lower wins, as on GNU ld's command line. `resolve::prio`, `prio_file`, `prio_offset` |
| occurrence (`Occ`) | one object's mention of a global symbol, defining or referring |
| kind | what an occurrence is: `DEF`, `WEAK`, `COMMON`, `COMDAT`, `UNDEF`, `LAZY` (an archive index entry), `SHARED` (a shared library's definition), `DSO_REF` (a shared library's reference), `INDIRECT`/`INDIRECT_DEF` (of a library only a shared library needs), `SHLIB_DEF` (of a hidden version) |
| export, id | the shards numbering their symbols in canonical order, shard after shard: a symbol's id is its index in main's `defs` |
| class | the output section an input section goes to (`layout::TEXT`, `RODATA`, ..., `NONALLOC` for debugging information) |
| key | what orders sections within a class: an `.init_array` priority, or the name for `__start_`/`__stop_` |
| place | an input section's address in the output, with its output section's index in the top 16 bits |
| delta | an output section's file offset minus its address: a place plus its delta is where its bytes go in the file |
| surely | the bytes the output takes whatever layout decides, which may be faulted in early |
| bound | the most the output can take, the size it is made at early |
| merge group | output section, character width and alignment of merged strings or constants |
| sidecar | `io.c`: the C functions Goose's standard library lacks (ranged reads, the mapped output, fork) |

## The build ID

The build ID is computed as the output is written: each write's XXH3 (the
hash lld's `--build-id=fast` uses; `xxh3.goose`, checked against libxxhash),
mixed with where it goes and its length, is added to a sum that each worker
and shard keeps and reports, and the ID comes from their total and the file's
size. Sums commute, so the ID does not depend on the thread count, and a
byte changed anywhere changes it. Reading the output back to hash it took
15 ms of the large link; this takes none of main's time. `--stats` prints when each round of resolution
ends; `--threads=N` sets the number of workers, which changes no byte of
the output. Not copied yet are the non-allocated sections:
`.note.stapsdt`, `.comment` and debugging information.

## The same output every time

Symbols are numbered in a canonical order, not the order they reach their
shards in. GOT slots, IFUNC stubs and common symbols are laid out in that
order, so the output is the same bytes from run to run; `test.py` checks
this.

## Shared libraries

As inputs, shared libraries are read only as far as their dynamic symbol
tables (`dso.goose`), each default-version definition a `SHARED` symbol,
below any object's definition. An archive member is still taken for a
symbol only a shared library later on the command line defines, as GNU ld
and lld do; `-l` prefers `.so`, scripts may name shared libraries, and
`--as-needed` (with `--push-state`, `AS_NEEDED`) keeps a library out of
`DT_NEEDED` unless something uses it.

As output (`-shared`), the base is 0 and in a shared library a global
symbol of default visibility is exported and preemptible. The shards
export what main needs to decide that, and main orders `.dynsym` (imports,
then exports by `.gnu.hash` bucket) and builds `.gnu.hash`, `.dynstr`'s
library and version names, `.gnu.version_r` and `.dynamic`; the shards
write their symbols' `.dynsym`, `.dynstr` and `.gnu.version` entries at the
places main gives them. Calls to preemptible functions go through PLT
entries that jump through GOT slots the dynamic linker binds at load
(`GLOB_DAT`); the general-dynamic and local-dynamic TLS models get their
GOT pairs (`DTPMOD64`, `DTPOFF64`). A worker describing an object counts its
sections' `R_X86_64_64` relocations, so that each object has its own range
of `.rela.dyn`, where its relocation job writes `RELATIVE` or symbolic
run-time relocations; main's own (the GOT's) come first.

`test.py` links a small library (exported data and functions, PLT calls,
run-time relocations, TLS, a constructor) and runs a program GNU ld links
against it, and compares its dynamic symbols and `DT_NEEDED` with GNU
ld's. The large link takes about 0.23 s, and programs loading the library
it makes run as with GNU ld's.

## PIE executables

With `-pie`, weld links a position-independent executable that the dynamic
linker loads: `-dynamic-linker`'s name in `.interp` and `PT_INTERP`, with
`PT_PHDR`, `DT_DEBUG` and `DF_1_PIE`, and otherwise the shared library's
tables and run-time relocations. What it defines nothing preempts, and it
exports only what the shared libraries it links define or use of it (as GNU
ld does; all with `--export-dynamic`): the shared libraries' undefined
symbols, too, go to the shards for that. So do those of the libraries the
given ones need, not given themselves, as GNU ld reads them: found by
their `DT_NEEDED` names in `-rpath-link`'s directories, `-rpath`'s, the
needing library's run path (`$ORIGIN` its own directory) and the system's,
round after round until none is new; their symbols only mark those already
in the shards, every object's by then, and define nothing (an object may
not use a library not given). A PIE that needs 40 such libraries reads them
in about 2 ms. weld grows its file descriptor table for them before
any thread starts: with threads, each doubling past 64 waits for an RCU
grace period, 10 to 15 ms. Its own TLS is found as in a static
executable. The PIEs weld has been checked on have GNU ld's dynamic
symbols, and run as GNU ld's do. What the given shared libraries use, not weakly, must be defined, as GNU
ld checks by default for an executable and with `--no-allow-shlib-undefined`
for a shared library: by an object visibly, or by any library, given or
needed, of whatever version; else weld names the library and the symbol.

gcc's position-independent code refers to a shared library's data directly
(`R_X86_64_PC32` to `stdout`, say), where clang's goes through the GOT; as
other linkers do, weld then copies the data into the executable's `.bss`
and has the dynamic linker fill the copy (`R_X86_64_COPY`): the executable
defines and exports the symbol, so the library uses the copy too. Every
symbol the library defines at that address shares it, as `environ`,
`__environ` and `_environ` do, so that a `setenv` in libc shows in the
program's `environ`. Only the shards know a library's symbols, so before
they finish main asks each which data a direct reference needs copied
(`CMD_COPY_KEYS`), and tells every shard which library addresses are copied
(`CMD_COPY`), which marks the aliases as well. A library's TLS that an
executable uses takes a GOT slot that the dynamic linker fills
(`R_X86_64_TPOFF64`), the instruction left as it is.
`--allow-shlib-undefined` turns it off. `--exclude-libs` hides
the definitions of the archives it names (or of all, with `ALL`): they are
not exported; a library that excludes a Rust archive so has GNU ld's
dynamic symbols but one, `__environ`, which GNU ld imports as the strong
alias of the `environ` used. weld refuses, rather than
links wrongly, an executable with shared libraries that is not PIE, a static
PIE, and a shared library's TLS used from an executable.

## Debugging information

Sections that are not loaded but kept (`.debug_*` and `.comment`, by name)
form one output section per name, after the segments in the file; an input
section's address in it is its offset, which is what DWARF's references
between sections count. Their relocations are plain values, never run-time
relocations. A reference into a section left out (a duplicate COMDAT
copy) gets the tombstone DWARF tools skip, as lld writes it: all ones, or
one less in `.debug_ranges` and `.debug_loc`. `llvm-dwarfdump --verify`
finds no error in the large link's (in GNU ld's, 91,137); gdb finds the same lines
in both.

## The output made early

Writing the output costs more in page faults than in relocating: each first
write to a page of the mapped file makes the kernel allocate it, about 3 us
apiece, half of the relocating workers' time on the large link. Faulting pages in
beforehand (`MADV_POPULATE_WRITE`) is no cheaper, but it can be done while
the workers would otherwise wait: main makes the output right after
resolution, at an upper bound of its size (every section kept, padded as
most, the linker's own tables as large as the symbols could make them), and
the idle workers fault in what it surely takes while main lays it out; it is
cut to size when laid out, and removed (a `defer`) if the link fails first.
Only the part it surely takes is faulted in, since cutting off pages faulted
in costs as much again. The large link: 262 to 249 ms.

Two workers fault it in, not all: each page faulted into the file takes
the lock of its page cache twice, adding the page and marking it dirty
(ext4 on Linux 6.8 caches a regular file in 4 KB pages), and with 13
workers faulting at once these were 8.5% of the link's processor time,
spinning, beside main on its core's other hyperthread. The large link: 39 jobs of
4 MB took 248 ms, four 243, two 240, one 252 (not done before relocation).

## Frame information

An FDE in `.eh_frame` of code left out, a duplicate COMDAT copy, is left
out with it, as GNU ld, lld and mold leave it out. The worker describing an
object puts each FDE's bytes on the section of the code it describes (the
relocation of its start names it); main, leaving a section out, takes them
off its object's `.eh_frame`; and the worker relocating the object copies
the records it keeps, each relocated where it goes, its pointer to its CIE
set anew. `.eh_frame`'s sections are packed 4-byte aligned, since a zero
word between them would end the table. The large link's `.eh_frame` goes from 6.05
MB (49,014 FDEs of code left out) to 4.24 MB, mold's 4.19 MB; the
remaining difference is a CIE an object, 2,176 of them, where mold keeps 2.

## Merged strings and constants

Sections of strings (`SHF_MERGE` and `SHF_STRINGS`: `.debug_str`,
`.debug_line_str`, `.comment`, the `.rodata.str*` of string literals) keep
one copy of each string (`merge.goose`), and sections of constants
(`SHF_MERGE` alone, `.rodata.cst*`) one copy of each constant, split every
`entsize` bytes. A worker describing an object
splits them into strings and sends each to the shard its XXH3 picks; the
shard keeps one copy, comparing bytes, ordered by first use, so the output
does not depend on the threads. Main lays out each merge group (output
section, character width, alignment) as one section and gives each
relocation job its strings' addresses; references into merged strings,
through a section symbol plus an addend or through a local label, go to
the copy, as lld maps them; the shards write the strings. A section in a
COMDAT group, with relocations of its own or a global symbol in it is
copied as it is. Unlike GNU ld, no string is stored as the tail of another,
as mold and wild do it. The large link's `.debug_str` goes from 18.9 MB to 10.4 MB
(wild's and mold's size), its output from 225 MB to 212 MB; it costs about
20 ms of the link, of some 390 ms of processor time over the threads.
