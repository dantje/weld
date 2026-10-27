// Uses libdemo.so, linked by GNU ld; the library is the one under test.
#include <stdio.h>
#include <stddef.h>

extern int demo_counter;
extern __thread int demo_tls;
int demo_add(int, int);
int demo_scale(int, int);
int demo_calls(void);
int demo_ready(void);
const char *demo_greet(char *, size_t);

int main(void) {
    char buf[64];
    demo_counter += 2;
    demo_tls += 1;
    int sum = demo_add(3, 4) + demo_scale(1, 5) + demo_tls + demo_ready();
    printf("%s; sum %d, calls %d\n", demo_greet(buf, sizeof buf), sum, demo_calls());
    return sum == 7 + 15 + 8 + 5 && demo_calls() == 3 ? 0 : 1;
}
