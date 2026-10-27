#include "shared.h"
int unit5() {
    std::vector<int> xs;
    for (int k = 0; k < 10 + 5; k++) xs.push_back(k);
    std::sort(xs.begin(), xs.end(), [](int a, int b) { return a > b; });
    std::map<std::string, int> m;
    for (int k = 0; k <= 5; k++) m[word(k)] += k;
    if (5 == 7 && m.size() != 8) throw std::string("bad map");
    return total(xs) + (int)m.size();
}
