#include "include/Disassembler.hpp"

Disassembler::Disassembler() {
    init();
}

void Disassembler::init() {
    if(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        std::cerr << "Failed to initialize disassembler" << std::endl;
        exit(1);
    }
}

Disassembler::~Disassembler() {
    if(cs_close(&handle) != CS_ERR_OK) {
        std::cerr << "Failed to close disassembler" << std::endl;
        exit(1);
    }
}

size_t Disassembler::disassemble(const uint8_t* p_code, size_t p_codeSize, cs_insn** p_instructions) {
    size_t count = 0;
    count = cs_disasm(handle, p_code, p_codeSize, 0, 0, p_instructions);
    return count;
}