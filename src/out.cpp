#include "out.hpp"
#include <cstdio>
#include <cstring>

static std::string Hex(uint8_t v) {
    char b[4]; snprintf(b, sizeof b, "%02X", v); return b;
}

void PrintText(const Elf& e, const Symbol& sym, const Sig& s) {
    (void)e;
    printf("sigmaker by swivel (@emptyworth on Discord)\n\n");
    printf("symbol: %s\n", sym.name.c_str());
    printf("addr:   0x%llx\n", (unsigned long long)sym.addr);
    printf("size:   %llu\n", (unsigned long long)sym.size);
    printf("siglen: %zu\n", s.pat.size());
    printf("\npattern:\n");
    for (size_t i = 0; i < s.pat.size(); i++) {
        if (i && i % 16 == 0) printf("\n");
        printf(s.mask[i] ? "?? " : "%s ", Hex(s.pat[i]).c_str());
    }
    printf("\n\ncompact:\n");
    for (size_t i = 0; i < s.pat.size(); i++)
        printf(s.mask[i] ? "??" : "%s", Hex(s.pat[i]).c_str());
    printf("\n");
}

void PrintJson(const Elf& e, const Symbol& sym, const Sig& s) {
    (void)e;
    printf("{\n");
    printf("  \"symbol\": \"%s\",\n", sym.name.c_str());
    printf("  \"addr\": \"0x%llx\",\n", (unsigned long long)sym.addr);
    printf("  \"size\": %llu,\n", (unsigned long long)sym.size);
    printf("  \"pattern\": \"");
    for (size_t i = 0; i < s.pat.size(); i++)
        printf(s.mask[i] ? "??" : "%s", Hex(s.pat[i]).c_str());
    printf("\"\n}\n");
}
