#include "include/TUI.hpp"

void tui::printWithPrompt(const std::string& p_message)
{
    if(!p_message.empty())
    {
        std::cout << p_message << std::endl;
    }
    std::cout << "(sdb) ";
}
void tui::printFill(char c, size_t count)
{
    for(size_t i = 0; i < count; i++)
    {
        std::cout << c;
    }
}
void tui::printRegisters(const user_regs_struct& p_regs)
{
    std::cout  << std::hex;
    std::cout << std::left << std::setw(8) << std::setfill(' ') << "$rax" << std::setw(2) << "0x" << std::right << std::setw(16) << std::setfill('0') << p_regs.rax << '\t';
    std::cout << std::left << std::setw(8) << std::setfill(' ') << "$rbx" << std::setw(2) << "0x" << std::right << std::setw(16) << std::setfill('0') << p_regs.rbx << '\t';
    std::cout << std::left << std::setw(8) << std::setfill(' ') << "$rcx" << std::setw(2) << "0x" << std::right << std::setw(16) << std::setfill('0') << p_regs.rcx << std::endl;

    std::cout << std::left << std::setw(8) << std::setfill(' ') << "$rdx" << std::setw(2) << "0x" << std::right << std::setw(16) << std::setfill('0') << p_regs.rdx << '\t';
    std::cout << std::left << std::setw(8) << std::setfill(' ') << "$rsi" << std::setw(2) << "0x" << std::right << std::setw(16) << std::setfill('0') << p_regs.rsi << '\t';
    std::cout << std::left << std::setw(8) << std::setfill(' ') << "$rdi" << std::setw(2) << "0x" << std::right << std::setw(16) << std::setfill('0') << p_regs.rdi << std::endl;

    std::cout << std::left << std::setw(8) << std::setfill(' ') << "$rbp" << std::setw(2) << "0x" << std::right << std::setw(16) << std::setfill('0') << p_regs.rbp << '\t';
    std::cout << std::left << std::setw(8) << std::setfill(' ') << "$rsp" << std::setw(2) << "0x" << std::right << std::setw(16) << std::setfill('0') << p_regs.rsp << '\t';
    std::cout << std::left << std::setw(8) << std::setfill(' ') << "$r8" << std::setw(2) << "0x" << std::right << std::setw(16) << std::setfill('0') << p_regs.r8 << std::endl;

    std::cout << std::left << std::setw(8) << std::setfill(' ') << "$r9" << std::setw(2) << "0x" << std::right << std::setw(16) << std::setfill('0') << p_regs.r9 << '\t';
    std::cout << std::left << std::setw(8) << std::setfill(' ') << "$r10" << std::setw(2) << "0x" << std::right << std::setw(16) << std::setfill('0') << p_regs.r10 << '\t';
    std::cout << std::left << std::setw(8) << std::setfill(' ') << "$r11" << std::setw(2) << "0x" << std::right << std::setw(16) << std::setfill('0') << p_regs.r11 << std::endl;

    std::cout << std::left << std::setw(8) << std::setfill(' ') << "$r12" << std::setw(2) << "0x" << std::right << std::setw(16) << std::setfill('0') << p_regs.r12 << '\t';
    std::cout << std::left << std::setw(8) << std::setfill(' ') << "$r13" << std::setw(2) << "0x" << std::right << std::setw(16) << std::setfill('0') << p_regs.r13 << '\t';
    std::cout << std::left << std::setw(8) << std::setfill(' ') << "$r14" << std::setw(2) << "0x" << std::right << std::setw(16) << std::setfill('0') << p_regs.r14 << std::endl;

    std::cout << std::left << std::setw(8) << std::setfill(' ') << "$r15" << std::setw(2) << "0x" << std::right << std::setw(16) << std::setfill('0') << p_regs.r15 << '\t';
    std::cout << std::left << std::setw(8) << std::setfill(' ') << "$rip" << std::setw(2) << "0x" << std::right << std::setw(16) << std::setfill('0') << p_regs.rip << '\t';
    std::cout << std::left << std::setw(8) << std::setfill(' ') << "$eflags" << std::setw(2) << "0x" << std::right << std::setw(16) << std::setfill('0') << p_regs.eflags << std::endl;

    std::cout << std::right << std::dec;
}

void tui::printInstruction(cs_insn p_instruction, uint64_t start)
{
    std::cout << std::setw(12) << std::setfill(' ') << std::hex << p_instruction.address << ": ";
    for(size_t i = 0; i < p_instruction.size; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)p_instruction.bytes[i] << " ";
    }
    printFill(' ', 32 - p_instruction.size * 3);
    std::cout << std::dec << '\t' << std::setw(10) << std::setfill(' ') << std::left << p_instruction.mnemonic;
    std::cout << p_instruction.op_str;
    std::cout << std::right << std::endl;
}

void tui::printBreakpoint(std::vector<std::pair<uint64_t, uint64_t>> p_breakpoints)
{
    std::cout << std::left;
    std::cout << std::setw(8) << std::setfill(' ') << "Num" << "Address" << std::endl;
    for(size_t i = 0; i < p_breakpoints.size(); i++)
    {
        std::cout << std::setw(8) << std::setfill(' ') << p_breakpoints[i].first << "0x" << std::hex << p_breakpoints[i].second << std::endl;
    }
    std::cout << std::right;
}