#pragma once
#include "types.hpp"
bool LoadElf(const char* path, Elf& e);
const Symbol* FindSym(const Elf& e, const std::string& name);
const Section* FindSec(const Elf& e, const std::string& name);
