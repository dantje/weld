# Working on weld

weld is a fast x86-64 ELF linker in Goose. Read [docs/design.md](docs/design.md)
first: it explains the threads, the phases, the messages between threads, and
the words the code uses (prio, place, delta, class, surely, ...).

## Commands

| Command | What it does |
|---|---|
| `make` | builds `./weld` with the `goose` on PATH (`GOOSE=...` for another) |
| `make test` / `make quick` | `tests/test.py`: readelf and GNU ld comparisons, links that run, fuzzing (1,000 or 50 corrupted inputs) |
| `make format` | `goose format --check .`; `goose format .` fixes the layout |
| `python3 bench/same.py [--dir DIR] REF NEW RSP...` | REF's output against NEW's, byte for byte, 1 thread and all, for each link (an ld response file, run in DIR) |
| `python3 bench/ab.py [--dir DIR] RSP EXE...` | alternating timings of a link, medians: the way to compare speed |
| `./weld link --stats --no-fork @RSP` | when each phase of a link ends |

A link to measure is a response file of ld's arguments: `clang -### ...`
prints the command a compiler runs, or `-Wl,@file` takes one. Use large
links: a few thousand objects.

## Every change

1. `goose format .`, then `make` and `make quick` (`make test` before a commit).
2. If it must not change the output: `cp weld /tmp/ld.ref` before, then
   `python3 bench/same.py /tmp/ld.ref ./weld RSP...` after. The output never
   depends on the number of threads; `same.py` checks that too.
3. If it changes the output: compare the dynamic symbols (`readelf
   --dyn-syms -W`) and `DT_NEEDED` of shared libraries and PIEs with GNU
   ld's, run what was linked, and check the debugging information
   (`llvm-dwarfdump --verify`).
4. If it could change speed: `python3 bench/ab.py RSP /tmp/ld.ref ./weld`
   (30 rounds). A machine's speed drifts by several percent over a minute:
   never compare two benchmarks run one after the other.
5. Commit with a message saying what changed and the measured effect.

## House rules

* **Correct, then fast.** Keep what real linkers do (string merging,
  `--no-allow-shlib-undefined`, ...) even when it costs time; win the time
  back elsewhere.
* **Judge speed by large links** (thousands of objects, hundreds of MB of
  output), not by hello world.
* **When a measurement disproves a hypothesis, report it and stop.** Revert,
  write it into [docs/numbers.md](docs/numbers.md) under "Tried, and did not
  help", and do not pile further experiments on it unasked.
* **Goose and its runtime belong to someone else.** Changes to them are
  proposals, written when asked. Work with what Goose offers: no heap, no
  shared memory, flat messages, one growable array per struct; `io.c` is
  the C sidecar for what the standard library lacks.
* **Comments say why**, in prose, with the figures that justified a choice.

## Where things are

The sources are in `src/`; the tests in `tests/`, with their inputs in
`tests/data/`; the benchmark and comparison scripts in `bench/`.

| To change | Look in |
|---|---|
| starting up: ld mode, subcommands, fork | `weld.goose` |
| the command line, `@file`s, `-l` lookup, linker scripts, `--dependency-file` | `options.goose` |
| `dump`, `scan`, `hash` | `tools.goose` |
| the messages between main and the workers | `protocol.goose` (`Job`, `ObjInfo`, `Sec`, ...) |
| what a worker does with a job: reading objects, describing sections, relocating | `worker.goose` (`run_job`, `read_object`, `describe`, `relocate`) |
| main's phases | `link.goose` (`run`) |
| symbol resolution rules: kinds, which definition wins, what is exported or emitted | `symbols.goose` |
| the shards: their messages, the table, flush, finish, export, merged strings, symbol tables | `resolve.goose` (`shard_loop`: `add`, `on_flush`, `on_finish`, `on_export`) |
| relocation types | `reloc.goose` (`apply`) |
| output sections, segments, headers | `layout.goose` |
| `.dynamic`, `.gnu.hash`, versions | `dynamic.goose`, and `link.goose` |
| shared libraries as inputs | `dso.goose` |
| ELF and `ar` parsing | `elf.goose`, `archive.goose` |
| `.eh_frame` | `ehframe.goose` |
| merged strings | `merge.goose`, and the shards in `resolve.goose` |
| the build ID's hash | `xxh3.goose` |
| reading files, the mapped output, fork | `io.c` |
| tests | `tests/test.py`, inputs in `tests/data/` |
