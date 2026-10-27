// A shared library for the linker's tests: exported functions and data,
// calls to libc and to its own exported function (through the PLT, since
// either could be preempted), a table of function pointers (run-time
// relocations), thread-local storage of both dynamic models, and a
// constructor.
#include <stdio.h>
#include <string.h>

int demo_counter = 40;
static __thread int calls;                 // local-dynamic: only this library sees it
__thread int demo_tls = 7;                 // general-dynamic: exported

static int twice(int x) { return 2 * x; }
static int thrice(int x) { return 3 * x; }
static int (*const table[])(int) = { twice, thrice };

int demo_scale(int i, int x) { calls++; return table[i & 1](x); }

int demo_add(int a, int b) {
    calls++;
    return a + b + demo_scale(0, 1) - 2;   // a call to an exported function: through the PLT
}

int demo_calls(void) { return calls; }

const char *demo_greet(char *buf, size_t n) {
    snprintf(buf, n, "hello from %s, counter %d", "libdemo", demo_counter);
    return buf;
}

static int ready;
__attribute__((constructor)) static void init(void) { ready = (int)strlen("ready"); }
int demo_ready(void) { return ready; }
