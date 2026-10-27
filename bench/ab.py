#!/usr/bin/env python3
"""A/B timing of weld binaries on one link.

  python3 bench/ab.py [--rounds N] [--dir DIR] RSP EXE...

Links RSP (a response file of ld's arguments, run in DIR) with each EXE
once per round, alternating, for N rounds (30) after two to warm up, and
prints each one's median and quartiles. Alternating matters: a machine's
speed drifts by several percent over a minute, enough to fake a difference
between benchmarks run one after the other.
"""
import os, statistics, sys, time
from common import run, options

cwd, rounds, args = options(sys.argv[1:], __doc__)
if len(args) < 2:
    sys.exit(__doc__)
rsp, exes = args[0], [os.path.abspath(e) for e in args[1:]]
times = {e: [] for e in exes}
for r in range(rounds + 2):
    for e in exes:
        t = time.perf_counter()
        run(e, rsp, cwd)
        if r >= 2:
            times[e].append((time.perf_counter() - t) * 1000)
for e in exes:
    q = statistics.quantiles(times[e], n=4)
    print(f'{e}: median {statistics.median(times[e]):6.1f} ms (quartiles {q[0]:.1f}-{q[2]:.1f})')
