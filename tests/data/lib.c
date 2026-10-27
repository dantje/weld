// The other half of start.c: data, read-only data and a system call.
static const char message[] = "hello from a Goose-linked program\n";
static const long table[] = { 1, -2, 3 };
long tally;                          // common with -fcommon

const char *greeting(void) { return message; }

long sum_table(void) {
    long s = 0;
    for (int i = 0; i < 3; i++) s += table[i];
    tally += s;
    return s;
}

long syscall3(long n, long a, long b, long c) {
    long r;
    __asm__ volatile ("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return r;
}
