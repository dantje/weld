#include <cstdio>
#include "shared.h"
int main() {
    int sum = unit0() + unit1() + unit2() + unit3() + unit4() + unit5() + unit6() + unit7();
    std::printf("sum %d, calls %d\n", sum, calls());     // calls is 8 only if every unit shares one counter
    return calls() == 8 ? 0 : 1;
}
