// gcc's position-independent code refers to a shared library's data
// directly (R_X86_64_PC32), which the link copies into the executable
// (R_X86_64_COPY), and to its TLS through the GOT (R_X86_64_GOTTPOFF).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
extern int lib_data;
extern int lib_array[4];
extern __thread int lib_tls;
extern int lib_func(int);
extern int lib_read(void);
extern char **environ;

int main(void) {
    lib_data = 100;                              // the library sees the same copy
    setenv("WELD_GCC_PIE", "1", 1);              // libc sets __environ, an alias of environ
    int seen = 0;
    for (char **e = environ; *e; e++) if (strncmp(*e, "WELD_GCC_PIE=", 13) == 0) seen = 1;
    fprintf(stdout, "%d %d %d %d %d %s\n", lib_read(), lib_array[2], lib_tls, lib_func(1), lib_data,
            seen ? "environ" : "no environ");
    return 0;
}
