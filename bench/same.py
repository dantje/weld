#!/usr/bin/env python3
"""Checks that a change to weld changed no byte of its output.

  python3 bench/same.py [--dir DIR] REF NEW RSP...

Links each RSP (a response file of ld's arguments, run in DIR) with the
weld binary REF and with NEW, each with one thread and with the default
count, and compares the outputs. Build REF from the commit before a change
first: cp weld /tmp/ld.ref. Exits 1 on any difference.
"""
import hashlib, os, sys
from common import output_of, run, options

cwd, _, args = options(sys.argv[1:], __doc__)
if len(args) < 3:
    sys.exit(__doc__)
ref, new, rsps = os.path.abspath(args[0]), os.path.abspath(args[1]), args[2:]
differ = 0
for rsp in rsps:
    out = output_of(rsp, cwd)
    sums = []
    for exe in (ref, new):
        for threads in ('--threads=1', None):
            run(exe, rsp, cwd, *([threads] if threads else []))
            sums.append(hashlib.sha1(open(out, 'rb').read()).hexdigest()[:16])
    same = len(set(sums)) == 1
    differ += not same
    print(f'{rsp}: {"the same" if same else "DIFFERENT"} ({" ".join(sums)}: ref 1 thread, ref, new 1 thread, new)')
sys.exit(1 if differ else 0)
