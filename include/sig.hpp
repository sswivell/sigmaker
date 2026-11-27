#pragma once
#include "types.hpp"
Sig BuildSig(const Elf& e, uint64_t start, uint64_t len, bool wildZero, int context);
Sig TrimSig(const Elf& e, const Sig& s);
