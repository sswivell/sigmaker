#pragma once
#include "types.hpp"
#include <vector>
std::vector<Hit> CountSig(const Elf& e, const Sig& s, int maxhits);
bool IsUnique(const Elf& e, const Sig& s);
