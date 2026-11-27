#include "elf.hpp"
#include "scan.hpp"
#include "sig.hpp"
#include "out.hpp"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cctype>
#include <string>

static void usage() {
    printf("sigmaker - byte signature generator\n");
    printf("by swivel (@emptyworth on Discord)\n\n");
    printf("usage:\n");
    printf("  sigmaker <binary> --name <symbol> [opts]\n");
    printf("  sigmaker <binary> --addr 0x<addr> [opts]\n");
    printf("opts:\n");
    printf("  --len N        initial signature length (default 32)\n");
    printf("  --wild-zero    wildcard 0x00 bytes\n");
    printf("  --ctx N        context bytes prepended (default 0)\n");
    printf("  --json         JSON output\n");
    printf("  --credits      credits\n");
    printf("  --help         help\n");
}

static void credits() {
    printf("sigmaker by swivel (@emptyworth on Discord)\n");
    printf("say hi on discord: @emptyworth\n");
}

static uint64_t parsehex(const char* s) {
    if (!s) return 0;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    return (uint64_t)strtoull(s, nullptr, 16);
}

int main(int argc, char** argv) {
    if (argc < 3) { usage(); return 1; }
    for (int i = 1; i < argc; i++)
        if (!strcmp(argv[i], "--credits")) { credits(); return 0; }
    const char* path = argv[1];
    const char* name = nullptr;
    const char* addr = nullptr;
    int len = 32;
    int ctx = 0;
    bool wz = false;
    bool json = false;
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--name") && i+1 < argc) name = argv[++i];
        else if (!strcmp(argv[i], "--addr") && i+1 < argc) addr = argv[++i];
        else if (!strcmp(argv[i], "--len") && i+1 < argc) len = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--ctx") && i+1 < argc) ctx = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--wild-zero")) wz = true;
        else if (!strcmp(argv[i], "--json")) json = true;
        else if (!strcmp(argv[i], "--help")) { usage(); return 0; }
    }
    if (!name && !addr) { usage(); return 1; }

    Elf e;
    if (!LoadElf(path, e)) return 1;

    Symbol sym{};
    if (name) {
        const Symbol* s = FindSym(e, name);
        if (!s) { fprintf(stderr, "sigmaker: symbol %s not found\n", name); return 1; }
        sym = *s;
    } else {
        sym.addr = parsehex(addr);
        sym.name = "?";
        sym.size = len;
        if (e.secs.size() > 0) {
            for (auto& s : e.syms) {
                if (s.addr <= sym.addr && s.addr + s.size > sym.addr) {
                    sym.name = s.name;
                    if (s.size > 0) sym.size = s.addr + s.size - sym.addr;
                    break;
                }
            }
        }
    }

    uint64_t start = sym.addr;
    if (start == 0) {
        fprintf(stderr, "sigmaker: cannot determine file offset for 0x%llx\n",
                (unsigned long long)sym.addr);
        return 1;
    }

    Sig s = BuildSig(e, start, len, wz, ctx);
    s = TrimSig(e, s);

    if (json) PrintJson(e, sym, s);
    else      PrintText(e, sym, s);

    return 0;
}
