#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

struct Section {
    std::string name;
    uint32_t    type;
    uint64_t    addr;
    uint64_t    off;
    uint64_t    size;
    uint32_t    link;
};

struct Symbol {
    std::string name;
    uint64_t    addr;
    uint64_t    size;
    int         shndx;
};

struct Reloc {
    uint64_t    off;
    uint32_t    type;
    uint64_t    symidx;
    int64_t     addend;
};

struct Elf {
    std::vector<uint8_t> data;
    bool     is64;
    bool     le;
    uint16_t machine;
    uint16_t etype;
    uint64_t entry;
    std::vector<Section> secs;
    std::vector<Symbol>  syms;
    std::vector<Reloc>   rels;
    const uint8_t* base() const { return data.data(); }
    size_t size() const { return data.size(); }
};

struct Sig {
    std::vector<uint8_t> pat;
    std::vector<uint8_t> mask;
    uint64_t             start;
    uint64_t             len;
};

struct Hit {
    uint64_t off;
    int      count;
};
