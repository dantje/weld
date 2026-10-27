#include "shared.h"
int unit7() {
    std::vector<int> xs;
    for (int k = 0; k < 10 + 7; k++) xs.push_back(k);
    std::sort(xs.begin(), xs.end(), [](int a, int b) { return a > b; });
    std::map<std::string, int> m;
    for (int k = 0; k <= 7; k++) m[word(k)] += k;
    if (7 == 7 && m.size() != 8) throw std::string("bad map");
    return total(xs) + (int)m.size();
}
