#include "scan.hpp"
#include <cstring>

std::vector<Hit> CountSig(const Elf& e, const Sig& s, int maxhits) {
    std::vector<Hit> out;
    if (s.pat.empty() || s.pat.size() > e.size()) return out;
    size_t end = e.size() - s.pat.size();
    for (size_t i = 0; i <= end; i++) {
        bool ok = true;
        for (size_t j = 0; j < s.pat.size(); j++) {
            if (s.mask[j]) continue;
            if (e.base()[i+j] != s.pat[j]) { ok = false; break; }
        }
        if (ok) {
            out.push_back(Hit{(uint64_t)i, 1});
            if ((int)out.size() >= maxhits) break;
        }
    }
    return out;
}

bool IsUnique(const Elf& e, const Sig& s) {
    auto h = CountSig(e, s, 2);
    return h.size() == 1;
}
