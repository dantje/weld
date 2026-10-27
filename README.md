<p align="center"><img src="weld.png" alt="weld" width="200"></p>

# weld

weld is a fast linker for x86-64 ELF on Linux, written in
[Goose](https://github.com/aardappel/goose) and designed around what Goose
provides: no heap, no memory shared between threads, typed queues between
them. It reads relocatable objects, `ar` archives, linker scripts such as
glibc's `libc.so`, and shared libraries, and links static executables,
position-independent executables and shared libraries. Compilers run it as
their linker (`-fuse-ld`); it takes GNU ld's command line.

This is version 0.1.

## Speed

On a 10-core Xeon E5-2680 v2 (20 threads), Linux 6.8, files in the page
cache, each linker at its default thread count:

| Link | weld 0.1 | wild 0.11 | mold 3.0 | GNU ld 2.42 |
|---|---|---|---|---|
| A C++ shared library: 2,266 objects, 178,532 global symbols, 210 MB output | 231 ms | 184 ms | 268 ms | 4.2 s |
| A C++ position-independent executable linking 40 shared libraries | 26.5 ms | 19.8 ms | 66.5 ms | |
| A C++ project's 44 libraries and executables, relinked under ninja | 0.93 s | | | 7.6 s |

The outputs have GNU ld's dynamic symbols, and their debugging information
verifies (`llvm-dwarfdump --verify`). [docs/numbers.md](docs/numbers.md)
has the measurements behind these, and the experiments that did not help.

## Building and installing

weld needs the Goose compiler on PATH (or in `$GOOSE`), and a C compiler,
which `goose build` uses.

```
git clone https://github.com/dantje/weld
cd weld
make                       # builds ./weld
make install               # into /usr/local (PREFIX=...): bin/weld, bin/ld.weld, libexec/weld/ld
make test                  # needs gcc, g++, clang, readelf and python3
```

## Using it

As a compiler's linker:

```
clang -fuse-ld=/usr/local/bin/ld.weld main.c -o main
gcc -B/usr/local/libexec/weld main.c -o main
```

gcc's `-fuse-ld` takes only the linkers it knows by name, so gcc is given
a directory in which weld is called `ld`.

Started as `ld` or `ld.*`, weld takes ld's arguments alone, as a compiler
driver passes them, response files (`@file`) included, and prints nothing
for a link that succeeds. As `weld`, it has subcommands:

```
weld link -o out <ld's arguments>        # link
weld resolve [--trace] <ld's arguments>  # resolve symbols only, and say what archive members it takes
weld dump file.o lib.a ...               # symbol tables, as readelf -sW prints them
weld scan file.o lib.a ...               # read every object and member on every core, timed
```

Besides ld's usual options it takes `--stats` (when each phase of the link
ends), `--threads=N` (the number of workers, which changes no byte of the
output) and `--no-fork` (like mold and wild, weld forks first and the
caller's wait ends as soon as the output is complete; this links in one
process).

## What it does and does not do yet

It links, as GNU ld does: archive members taken as needed, COMDAT groups
kept once, `.eh_frame` without the frames of code left out and with
`.eh_frame_hdr`, merged strings and constants, IFUNCs, TLS in every model,
`--as-needed`, `--exclude-libs`, `--export-dynamic`,
`--no-allow-shlib-undefined`, symbol versions, `--build-id` and
`--dependency-file`; copy relocations for the shared libraries' data that
gcc's position-independent code refers to directly, and a shared library's
TLS used from an executable; debugging information with the tombstones
DWARF tools expect. The output is the same bytes whatever the number of
threads. weld links itself, through gcc and through clang, and the weld it
links links itself into the same bytes.

Not yet:

* `.note.stapsdt`;
* executables that use shared libraries without being position-independent,
  and static PIEs (weld refuses them);
* a shared library's TLS used from an executable in a model other than
  initial-exec, which compilers use for it (weld refuses it).

## Reading on

* [docs/design.md](docs/design.md): how weld works: its threads and phases,
  the messages between them, the words the code uses, and each feature's
  design.
* [docs/numbers.md](docs/numbers.md): measurements, and what was tried and
  did not help.
* [CLAUDE.md](CLAUDE.md): working on weld: the commands, the checks a change
  must pass, and where to find what.

## License

MIT; see [LICENSE](LICENSE).
