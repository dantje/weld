// A shared library whose data, array, TLS and functions a gcc PIE uses
// (tests/test.py, check_gcc_pie).
int lib_data = 42;
int lib_array[4] = {1, 2, 3, 4};
__thread int lib_tls = 7;
int lib_func(int x) { return x + 1; }
int lib_read(void) { return lib_data; }
