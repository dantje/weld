#include "shared.h"
int unit3() {
    std::vector<int> xs;
    for (int k = 0; k < 10 + 3; k++) xs.push_back(k);
    std::sort(xs.begin(), xs.end(), [](int a, int b) { return a > b; });
    std::map<std::string, int> m;
    for (int k = 0; k <= 3; k++) m[word(k)] += k;
    if (3 == 7 && m.size() != 8) throw std::string("bad map");
    return total(xs) + (int)m.size();
}
