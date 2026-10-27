// Shared by every translation unit of the COMDAT test: templates and an
// inline function with a static local, each of which every unit
// instantiates, so the linker sees one copy per unit and must keep one.
#include <algorithm>
#include <map>
#include <string>
#include <vector>

inline int &calls() { static int n = 0; return n; }   // one counter, if there is one copy

template <typename T> T total(const std::vector<T> &xs) {
    ++calls();
    T t{};
    for (const T &x : xs) t += x;
    return t;
}

inline std::string word(int i) { return "w" + std::to_string(i); }

int unit0(); int unit1(); int unit2(); int unit3(); int unit4(); int unit5(); int unit6(); int unit7();
