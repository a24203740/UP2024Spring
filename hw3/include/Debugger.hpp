#pragma once

#include <sys/user.h>
#include <map>
#include <utility>
#include <algorithm>
#include "include/Disassembler.hpp"
#include "include/ProgramLoader.hpp"
#include "include/TUI.hpp"
#include "include/util.hpp"
#include "include/ELFparser.hpp"

class Debugger {
    public:
        Debugger();
        ~Debugger() = default;
        void loadProgram(const char* p_program);
        void run();
    private:
        bool isLoad;
        bool hitBreakpoint;
        uint64_t hitBreakpointAddress;
        uint64_t breakPointCount;
        user_regs_struct getRegs();
        std::string waitUserInput();
        bool waitStopAndParseSignal();
        size_t peekDataFromMemory(char* p_buffer, size_t p_size, unsigned long p_address);
        void Extract5Instructions();
        void stepOneInstruction();
        void continueExecution();
        void setBreakpoint(uint64_t p_address, bool p_addToMap = true);
        void removeBreakpoint(uint64_t p_address, bool p_removeFromMap = true);
        void hitBreakpointHandler(bool p_beforeInstruction = false);
        void patchMemory(uint64_t p_address, uint64_t p_data);
        void showBreakpointsInfo();
        cs_insn getInstruction(uint64_t p_address);
        std::map<uint64_t, std::pair<uint64_t, uint64_t>> breakpoints{}; // address -> original data, index
        Disassembler disassembler;
        ProgramLoader programLoader;
        ELFparser elfParser;
};