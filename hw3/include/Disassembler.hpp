#pragma once

#include "include/util.hpp"
#include <iostream>

#include <capstone/capstone.h>


class Disassembler {
    public:
        Disassembler();
        ~Disassembler();
        size_t disassemble(const uint8_t* p_code, size_t p_codeSize, cs_insn** p_instructions, uint64_t p_address);
    private:
        void init();
        csh handle;
};
