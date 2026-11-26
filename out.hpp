#pragma once
#include "types.hpp"
#include <string>
void PrintText(const Elf& e, const Symbol& sym, const Sig& s);
void PrintJson(const Elf& e, const Symbol& sym, const Sig& s);
