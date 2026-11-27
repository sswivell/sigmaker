#include "sig.hpp"
#include "scan.hpp"
#include <cstdio>
#include <cstring>

Sig BuildSig(const Elf& e, uint64_t start, uint64_t len, bool wz, int ctx) {
    Sig s{};
    s.start = start;
    if (start >= e.size()) return s;
    if (start + len > e.size()) len = e.size() - start;
    s.len = len;
    s.pat.assign(e.base() + start, e.base() + start + len);
    s.mask.assign(len, 0);
    for (auto& r : e.rels) {
        if (r.off >= start && r.off < start + len) {
            size_t o = (size_t)(r.off - start);
            int sz = 4;
            if (e.is64) {
                switch (r.type) {
                case 1: case 6: case 7: case 8: case 24: case 37: sz = 8; break;
                case 2: case 4: case 5: case 9: case 10: case 11: sz = 4; break;
                default: sz = 4;
                }
            }
            for (int j = 0; j < sz && o + j < len; j++) s.mask[o+j] = 1;
        }
    }
    if (wz) for (size_t i = 0; i < len; i++) if (s.pat[i] == 0) s.mask[i] = 1;
    for (int k = 0; k < ctx; k++) {
        Sig left{};
        left.pat.assign(e.base() + (start > (uint64_t)k ? start - k : 0),
                        e.base() + start);
        left.mask.assign(left.pat.size(), 0);
        left.start = start - k;
        left.len = k;
        Sig merged = left;
        merged.pat.insert(merged.pat.end(), s.pat.begin(), s.pat.end());
        merged.mask.insert(merged.mask.end(), s.mask.begin(), s.mask.end());
        merged.len = merged.pat.size();
        s = merged;
    }
    return s;
}

Sig TrimSig(const Elf& e, const Sig& s) {
    Sig out = s;
    while (out.pat.size() > 4) {
        Sig tryit = out;
        tryit.pat.pop_back();
        tryit.mask.pop_back();
        tryit.len = tryit.pat.size();
        auto h = CountSig(e, tryit, 2);
        if (h.size() > 1) break;
        out = tryit;
    }
    return out;
}
