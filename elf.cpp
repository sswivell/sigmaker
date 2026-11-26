#include "elf.hpp"
#include <cstdio>
#include <cstring>
#include <cstdlib>

static uint16_t R16(const Elf& e, const uint8_t* p) {
    return e.le ? (uint16_t)(p[0] | (p[1]<<8)) : (uint16_t)((p[0]<<8)|p[1]);
}
static uint32_t R32(const Elf& e, const uint8_t* p) {
    if (e.le) return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
    return ((uint32_t)p[0]<<24) | ((uint32_t)p[1]<<16) | ((uint32_t)p[2]<<8) | (uint32_t)p[3];
}
static uint64_t R64(const Elf& e, const uint8_t* p) {
    uint64_t lo, hi;
    if (e.le) { lo = R32(e, p); hi = R32(e, p+4); }
    else { hi = R32(e, p); lo = R32(e, p+4); }
    return lo | (hi << 32);
}

static const char* Str(const Elf& e, size_t off, const Section& s) {
    if (off >= s.size) return "";
    return (const char*)e.base() + s.off + off;
}

static void ParseSym(Elf& e, const Section& s) {
    if (s.link >= e.secs.size()) return;
    const Section& st = e.secs[s.link];
    size_t ent = e.is64 ? 24 : 16;
    if (s.size < ent) return;
    size_t n = s.size / ent;
    for (size_t i = 0; i < n; i++) {
        const uint8_t* p = e.base() + s.off + i * ent;
        Symbol sym{};
        uint32_t nameoff;
        if (e.is64) {
            nameoff = R32(e, p);
            uint8_t info = p[4];
            uint8_t shndx_hi = p[7];
            uint16_t shndx_lo = R16(e, p+6);
            sym.shndx = (shndx_lo & 0xffff) | ((shndx_hi & 0) << 16);
            sym.shndx = shndx_lo;
            sym.addr  = R64(e, p+8);
            sym.size  = R64(e, p+16);
            (void)info;
        } else {
            nameoff   = R32(e, p);
            sym.addr  = R32(e, p+4);
            sym.size  = R32(e, p+8);
            sym.shndx = R16(e, p+14);
        }
        sym.name = Str(e, nameoff, st);
        e.syms.push_back(sym);
    }
}

static void ParseRel(Elf& e, const Section& s, bool rela) {
    size_t ent = e.is64 ? (rela ? 24 : 16) : (rela ? 12 : 8);
    if (s.size < ent) return;
    size_t n = s.size / ent;
    for (size_t i = 0; i < n; i++) {
        const uint8_t* p = e.base() + s.off + i * ent;
        Reloc r{};
        if (e.is64) {
            r.off = R64(e, p);
            uint64_t info = R64(e, p+8);
            r.symidx = info >> 32;
            r.type   = (uint32_t)info;
            if (rela) r.addend = (int64_t)R64(e, p+16);
        } else {
            r.off = R32(e, p);
            uint32_t info = R32(e, p+4);
            r.symidx = info >> 8;
            r.type   = info & 0xff;
            if (rela) r.addend = (int32_t)R32(e, p+8);
        }
        e.rels.push_back(r);
    }
}

bool LoadElf(const char* path, Elf& e) {
    FILE* f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "sigmaker: cannot open %s\n", path); return false; }
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return false; }
    e.data.resize((size_t)sz);
    if (fread(e.data.data(), 1, e.data.size(), f) != e.data.size()) { fclose(f); return false; }
    fclose(f);
    if (e.data.size() < 16 || memcmp(e.data.data(), "\x7f""ELF", 4)) {
        fprintf(stderr, "sigmaker: not an ELF\n"); return false;
    }
    uint8_t cls = e.data[4], enc = e.data[5];
    if (cls != 1 && cls != 2) return false;
    if (enc != 1 && enc != 2) return false;
    e.is64 = (cls == 2);
    e.le   = (enc == 1);
    const uint8_t* p = e.data.data() + 16;
    e.etype   = R16(e, p);
    e.machine = R16(e, p+2);
    uint64_t shoff = e.is64 ? R64(e, p+16) : R32(e, p+12);
    uint16_t shentsize = e.is64 ? R16(e, p+36) : R16(e, p+34);
    uint16_t shnum     = e.is64 ? R16(e, p+38) : R16(e, p+36);
    uint16_t shstr     = e.is64 ? R16(e, p+40) : R16(e, p+38);
    e.entry = e.is64 ? R64(e, p+8) : R32(e, p+4);
    if (!shoff || !shnum || !shentsize) return true;
    if (shoff + (uint64_t)shentsize * shnum > e.size()) return false;
    for (int i = 0; i < shnum; i++) {
        const uint8_t* q = e.base() + shoff + i * shentsize;
        Section s{};
        s.name = "";
        uint32_t nameoff = R32(e, q);
        s.type  = R32(e, q+4);
        s.addr  = e.is64 ? R64(e, q+16) : R32(e, q+12);
        s.off   = e.is64 ? R64(e, q+24) : R32(e, q+16);
        s.size  = e.is64 ? R64(e, q+32) : R32(e, q+20);
        s.link  = R32(e, q+ (e.is64 ? 40 : 24));
        s.name  = std::to_string(nameoff);
        e.secs.push_back(s);
    }
    if (shstr < e.secs.size()) {
        const Section& st = e.secs[shstr];
        for (auto& s : e.secs) {
            uint32_t no = (uint32_t)std::stoul(s.name);
            s.name = Str(e, no, st);
        }
    }
    for (auto& s : e.secs) {
        if (s.type == 2 || s.type == 11) ParseSym(e, s);
        else if (s.type == 4) ParseRel(e, s, true);
        else if (s.type == 9) ParseRel(e, s, false);
    }
    return true;
}

const Symbol* FindSym(const Elf& e, const std::string& name) {
    for (auto& s : e.syms) if (s.name == name && s.shndx != 0) return &s;
    return nullptr;
}

const Section* FindSec(const Elf& e, const std::string& name) {
    for (auto& s : e.secs) if (s.name == name) return &s;
    return nullptr;
}
