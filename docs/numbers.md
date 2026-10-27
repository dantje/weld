# Numbers

Measurements behind weld's design, and the experiments that did not help,
so that none is tried again without a new reason. Machine: Xeon E5-2680 v2
(10 cores, 20 threads, SSE4.2 and AVX, no AVX2), Linux 6.8, ext4, inputs in
the page cache. How to measure is in [CLAUDE.md](../CLAUDE.md): this
machine's speed drifts by several percent over a minute, so compare by
alternating runs (`bench/ab.py`), not by benchmarks run one after another.

Most of the figures are of one link, the large link: a C++ shared library
of 2,266 objects (1,887 object files and two Rust archives), 178,532
global symbols, against 30 shared libraries; its output is about 210 MB,
most of it debugging information. The PIE is a C++ executable that needs
40 shared libraries besides the ones it is given.

## Now

| Link | weld | wild 0.11 | mold 3.0 | GNU ld 2.42 |
|---|---|---|---|---|
| The large link | 231 ms | 184 ms | 268 ms | 4.2 s |
| The PIE | 26.5 ms | 19.8 ms | 66.5 ms | |
| A C++ project's 44 libraries and executables, relinked through clang under ninja | 0.93 s | | | 7.6 s |

Of the relink's 0.93 s, 0.9 s is one chain of 11 links that wait for each
other, the large link among them, 300 ms of it.
Each link in it also pays about 22 ms for starting clang (`clang++-22
--version` alone takes that), which weld cannot change.

Before any thread starts, `options.goose` opens every input to read its
first bytes. One after another, the large link's 1,940 took 10 to 12 ms; the
sidecar now opens them at once on four to eight C threads
(`ld_open_all`), for links of 64 inputs or more: the large link 236.3 to
229.2 ms and 237.4 to 231.3 ms (`bench/ab.py`, 30 rounds each), the PIE
the same. Starting the 29 threads takes another 11 to 13 ms of main's time,
each start waiting on the lock the others' data stack mappings take, but
off the critical path: round one's jobs are queued before the first, which
starts reading at once.

## History

`weld scan` over 67 archives (4.0 GB: libc, libcrypto, ffmpeg, ICU, Qt 6,
ROCm), 10,535 objects, 3.6M sections, 3.0M symbols and 25.6M relocations,
on 20 threads, with the files in the page cache: **0.31 s, 11 GB/s**.

`weld resolve` with gcc's own command line for a static link takes exactly
GNU ld's 424 archive members for hello world, in 3.3 ms (12 rounds). For
the Goose compiler (5 objects, 21 archives including libstdc++, libc,
libm and SDL3) it takes 1,339 members and resolves 25,923 global symbols
in 11 ms.

Linking, as whole processes (hyperfine, 30 to 50 runs, files in the page
cache, 20 hardware threads, each linker at its default thread count), on
gcc's own command lines for the two static links. Every output runs, and
each linker's Goose compiler generates the same C. The outputs have the
same pieces: segments with RELRO, the merged property note, the inputs'
notes and a build ID (mold adds an `.eh_frame_hdr`, which gcc does not ask
for in a static link):

| Linker | hello world, glibc (430 objects) | the Goose compiler (1,349 objects, libstdc++, SDL3) |
|---|---|---|
| weld | **10.7 ms** | 44.9 ms |
| wild 0.11 | 12.1 ms | **35.1 ms** |
| mold 1.3 (C++) | 15.9 ms | 46.7 ms |
| mold 3.0 (Rust) | 38.1 ms | 74.9 ms |
| GNU ld 2.42 | 49.8 ms | 411.5 ms |

The large link, a shared library (1,887 objects and two Rust archives,
2,266 objects in all once 379 archive members are taken, against 30
shared libraries; 178,532 global symbols; output around 210 MB, most of it
debugging information), linked on its own `ld` command line through a
response file:

| Linker | The large link | Output |
|---|---|---|
| wild 0.11 | **182 ms** | 203 MB |
| mold 3.0 (Rust) | 268 ms | 211 MB |
| weld | 290 ms | 212 MB |
| mold 1.3 (C++) | 1,214 ms | 209 MB |
| GNU ld 2.42 | 4,217 ms | 209 MB |

(weld was 270 ms before it merged strings, with a 225 MB output; mold 1.3
and GNU ld as measured earlier.)

What made the difference here:

* **The output is mapped.** `io.c` maps it shared at creation, and a write
  to it is a `memcpy`. A `pwrite` per section was 15,000 system calls.
* **Inputs are told apart by their first 8 bytes**, not by reading them
  whole to see whether they are linker scripts.
* **Archive members are read in batches**, about two jobs a worker each
  round. The batch shares one buffer, which views of earlier members
  survive as it grows, and one message to each shard.

Where resolution's time goes, in the compiler's link (`--stats`): the
rounds themselves are cheap, a flush 20 to 90 µs, and the 1,339 members
cost 5 ms over all nine rounds after the first. The first round costs
twice that, since the compiler is one 7 MB object (10,508 sections, 74,963
relocations) that one worker reads alone. What helped:

* **Fewer threads.** Starting a Goose thread takes about 0.2 ms here: the
  runtime reserves each of its data stacks with a mapping of its own,
  under the lock that page faults take too. One worker per 8 MB of input
  (two at least) is faster than one per 4 MB. The number of shards follows
  the inputs' size alone, since symbols are numbered shard by shard.
* **The largest round-one job first**, queued before any thread starts.
* **Descriptions after the job is done.** A worker sends an object's
  symbols, reports the job done, and only then describes the object's
  sections for layout, so no round waits for that; main collects them
  after the last round, appending each object's sections at once.
* **Huge pages for the workers' buffers**, so a large read faults a few
  times instead of once per 4 KB.
* **Cheaper scanning**: a relocation's type is read alone until it is one
  that can need a GOT slot, and a batch for the shards is built from the
  records sorted by shard rather than one pass over them per shard.

Layout in main (`--stats` marks each step) took about 17 ms of serial work
on the compiler's link. What helped:

* **Sections placed without a full sort.** Only `.init_array` priorities
  and the sections `__start_` and `__stop_` name need ordering by key, so
  sections are bucketed by output section in command-line order, and only
  those few sorted.
* **The old output removed off the critical path.** Unlinking a 13.6 MB
  output frees its pages, which took 2.7 ms. `io.c` renames it when the
  link starts and removes it on a thread of its own, which the link waits
  for at the end.
* **Each section's place computed once**, into an array a relocation job
  copies its object's part of; object lookups remember the last one, as
  definitions and occurrences come in runs from one object.

Two things that did not help: batching relocation jobs (up to 64 objects
a job) balanced the workers worse and was slower; and the 45 to 1,349 job
messages still take about 3 ms of `qput` in main, which a different
`malloc` threshold did not change. That cost is in the runtime's queue
and is left for it.

## Tried, and did not help

Measured on the large link unless said otherwise.

* **Hot/cold split of `resolve::Def`**, with ordered per-shard receiving:
  "definitions received" 1.5 ms slower, nothing else changed.
* **Huge pages for main's data stack**: Goose keeps struct arrays on other
  data stacks than the `u8` array that would have asked for them.
* **glibc `malloc` huge pages for queue messages**: faster `qput`, the
  same total.
* **mmap for inputs instead of `pread`**: a C prototype reading all 1,885
  objects with 13 threads took 16.7 ms with `pread`, 35 ms with `mmap`,
  60 ms with `MAP_POPULATE`. So no zero-copy input proposal.
* **Writing the output from anonymous memory, then `pwrite`**: 145 ms
  against 55 ms into the shared mapping; huge pages slower still.
* **Partial reads in resolution** (only symbols, strings and relocated
  sections, 48% of the bytes): 274.9 against 275.2 ms. Round one is bound
  by processor time, not by reading.
* **8 shards instead of 16**: the same; 4: round one shorter, the link
  19 ms slower.
* **"Owner computes" layout** (fixed object ownership per worker, shards
  routing import values to owners): 336 against 331 ms; one relocation
  message per owner 349 ms. Fixed ownership loses the shared queue's
  balancing.
* **Batching relocation jobs** (up to 64 objects a job): balanced worse,
  slower.
* **Relocation jobs largest first** (Rust's std is one 12 MB object that
  came last and ran alone): 43.4 against 44.5 ms on a 105-object library
  that links Rust's std, noise; run beside the others, that job slowed
  from 7.6 to 12 ms. The write is bound by page faults, not by the order.
* **All 13 workers faulting the output in** (39 jobs of 4 MB): 248 ms; two
  jobs 240, four 243, one 252. Two it is.
* **SIMD for the build ID**: the build ID costs 2.4 ms in all (243.0 against
  245.4 ms with `--build-id=none`). libxxhash's SSE2 XXH3 is 1.46 times
  weld's scalar one (9.4 against 6.5 GB/s): 0.8 ms at most. BLAKE3 is
  slower than XXH3.
* **Goose's relative references (links) instead of indices**: weld's hot
  arrays hold no references, only indices, which a pool-relative link
  encodes the same way. Keeping every bounds check (`--no-bce`, 6,445 more
  than now) costs under 2%, so the unchecked loads links give are worth
  less.
* **Relocation jobs' tables owned by the sidecar** instead of copied into
  each job's message (main put each table in C once; a worker copied its
  parts back with `ld_table_get`): main's job building went from 16.9 to
  9.8 ms and its symbol values from 21.1 to 18.6, but waiting for the
  relocating workers from 20.5 to 44.0 ms, so the large link took 239.5
  against 229.4 ms (`bench/ab.py`, 30 rounds); the PIE the same. The workers'
  profile hardly changed, and the output's pre-faulting ended 6 to 10 ms
  before the first relocation job, so it is not contention with that.
  Timing each relocation job showed them no slower (median 140 against
  143 us, 770 against 743 ms in all, the same parallelism) and the span
  from the first queued to the last collected 59 against 61 ms; the time
  went after it, which ld_tables_free does not explain either: without
  it, 238.0 against 229.8 ms. Why it is slower is not known.
* **Indirect libraries creating no symbols in the shards**: no change.
  The cost of following `DT_NEEDED` was the file descriptor table growing
  past 64 with threads running (an RCU grace period, 15 ms), now grown
  before any thread starts.

## Where the time goes

The large link, `perf` over all threads: page faults on the output mapping 24% of
processor time (two thirds of it in the two pre-faulting workers), copies
14% (`pread` into buffers 6%, `memmove` 5%), relocation 6%, XXH3 3%, the
scan for strings' ends 2.4% (already SSE2 in Goose's runtime), queues 8.5%
(mostly waking threads). Main's serial phases are the critical path: in
them, building the relocation jobs copies 16.5 MB of main's tables into
messages (13 to 17 ms), since Goose threads share no memory.
