#pragma once

#include "util.hpp"

#include <capstone/capstone.h>
#include <iostream>
#include <iomanip>
#include <vector>
#include <utility>
#include <sys/user.h>

namespace tui {
    void printWithPrompt(const std::string& p_message);
    void printRegisters(const user_regs_struct& p_regs);
    void printInstruction(cs_insn p_instruction, uint64_t start);
    void printBreakpoint(std::vector<std::pair<uint64_t, uint64_t>> p_breakpoints);
    void printFill(char c, size_t count);
} // namespace tui