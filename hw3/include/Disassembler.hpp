#pragma once

#include "include/util.hpp"
#include <iostream>

extern "C" {
    #include <capstone/capstone.h>
}


class Disassembler {
    public:
        Disassembler();
        ~Disassembler() = default;
        size_t disassemble(const uint8_t* p_code, size_t p_codeSize, cs_insn** p_instructions);
    private:
        void init();
        csh handle;
};
