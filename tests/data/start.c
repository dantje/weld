// A program with no C library, for linking with ld: it writes through
// system calls and exits with a status that checks what it computed.
long syscall3(long n, long a, long b, long c);
const char *greeting(void);
long sum_table(void);

int counter = 40;          // .data
int zeroed;                // .bss
static long (*const ops[])(void) = { sum_table };    // R_X86_64_64 into .data.rel.ro

static long length(const char *s) {
    long n = 0;
    while (s[n]) n++;
    return n;
}

void _start(void) {
    const char *g = greeting();
    syscall3(1, 1, (long)g, length(g));
    long status = counter + zeroed + ops[0]();     // 40 + 0 + 2
    syscall3(60, status, 0, 0);
    for (;;) {}
}
