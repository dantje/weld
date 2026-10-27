"""What the bench scripts share: how to run a weld binary on a link given
as a response file of ld's arguments, and where that link's output goes."""
import os, shlex, subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # weld's checkout


def output_of(rsp_path, cwd):
    """The -o of the response file, as clang writes one or one argument a line."""
    words = shlex.split(open(rsp_path).read())
    return os.path.join(cwd, words[words.index('-o') + 1])


def command(exe, rsp_path, *flags):
    """A weld binary started as ld (ld, ld.*) takes ld's arguments alone; else `weld link`."""
    name = os.path.basename(exe)
    head = [exe] if name == 'ld' or name.startswith('ld.') else [exe, 'link']
    return head + list(flags) + ['@' + os.path.abspath(rsp_path)]


def run(exe, rsp_path, cwd, *flags):
    subprocess.run(command(exe, rsp_path, *flags), cwd=cwd, check=True, stdout=subprocess.DEVNULL)


def options(argv, doc):
    """--dir DIR (where the link runs, by default here) and --rounds N, then the rest."""
    cwd, rounds = os.getcwd(), 30
    while argv and argv[0].startswith('--'):
        if argv[0] == '--dir' and len(argv) > 1: cwd = argv[1]
        elif argv[0] == '--rounds' and len(argv) > 1: rounds = int(argv[1])
        else: raise SystemExit(doc)
        argv = argv[2:]
    return cwd, rounds, argv
