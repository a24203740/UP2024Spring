#pragma once

#include "util.hpp"

#include <capstone/capstone.h>
#include <iostream>
#include <iomanip>
#include <sys/user.h>

namespace tui {
    void printWithPrompt(const std::string& p_message);
    void printRegisters(const user_regs_struct& p_regs);
    void printInstruction(cs_insn p_instruction, uint64_t start);
    void printFill(char c, size_t count);
} // namespace tui