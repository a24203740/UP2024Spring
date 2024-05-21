#include "include/Debugger.hpp"
#include <utility>
#include <memory.h>
#include <capstone/capstone.h>

Debugger::Debugger()
{
    isLoad = false;
    hitBreakpoint = false;
    hitBreakpointAddress = 0;
    breakPointCount = 0;
}

void Debugger::loadProgram(const char* p_program)
{
    breakPointCount = 0;
    isLoad = false;
    elfParser.parse(p_program);
    if(!elfParser.isValid()) {
        std::cerr << "Invalid ELF file" << std::endl;
        return;
    }
    programLoader.setProgram(p_program);
    programLoader.load();
    if(!programLoader.isValid()) {
        std::cerr << "Failed to load program" << std::endl;
        return;
    }
    isLoad = true;
    std::cout << "** program \'" << p_program << "\' loaded. entry point " << 
        std::hex << "0x" << elfParser.getEntryPoint() << "."; 
    std::cout << std::dec << std::endl;
}

std::string Debugger::waitUserInput()
{
    std::string userInput;
    std::getline(std::cin, userInput);
    return userInput;
}

bool Debugger::waitStopAndParseSignal()
{
    int status;
    util::checkError(waitpid(programLoader.getPid(), &status, 0), "waitpid");
    if(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP){
        siginfo_t info{0};
        ptrace(PTRACE_GETSIGINFO, programLoader.getPid(), nullptr, &info); // Retrieve information about the signal that caused the stop
        if(info.si_signo != SIGTRAP) {
            std::cerr << "Unexpected signal" << std::endl;
            return false;
        }
        switch (info.si_code)
        {
        case TRAP_TRACE:
            // stop because PTRACE_SINGLESTEP
            return true;
        case TRAP_BRKPT:
        case SI_KERNEL:
            // stop because software breakpoint
            hitBreakpointHandler();
            return true;
        default:
            break;
        }
    }
    return false;
}

user_regs_struct Debugger::getRegs()
{
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, programLoader.getPid(), nullptr, &regs);
    return regs;
}

size_t Debugger::peekDataFromMemory(char* p_buffer, size_t p_size, unsigned long p_address)
{
    uint64_t start = elfParser.getTextSectionAddress();
    uint64_t end = start + elfParser.getTextSectionSize();
    if(p_address < start || p_address > end) {
        std::cerr << "Address out of text section" << std::endl;
        return 0;
    }
    if(p_size % sizeof(long) != 0) {
        std::cerr << "Address is not aligned" << std::endl;
        return 0;
    }
    uint64_t limit = std::min(p_size, end - p_address);
    for(size_t i = 0; i < limit; i += sizeof(long)) {
        errno = 0;
        long data = ptrace(PTRACE_PEEKDATA, programLoader.getPid(), p_address + i, nullptr);
        if(errno != 0) {
            perror("ptrace(PTRACE_PEEKDATA)");
            return i;
        }
        memcpy(p_buffer + i, &data, sizeof(long));
    }
    return limit;
}

void Debugger::Extract5Instructions()
{
    uint64_t rip = getRegs().rip;
    char buffer[96]; // instructions are at most 15 bytes long, 5 instructions = 75 bytes, 96 is enough
    size_t bytesRead = peekDataFromMemory(buffer, sizeof(buffer), rip);
    if(bytesRead == 0) {
        std::cerr << "Failed to read memory" << std::endl;
        return;
    }
    for(size_t i = 0; i < bytesRead; i++)
    {
        auto it = breakpoints.find(rip + i);
        if(it != breakpoints.end())
        {
            buffer[i] = it->second.first; // restore the original data
        }
    }
    cs_insn* insn;
    size_t count = 0;
    count = disassembler.disassemble(reinterpret_cast<uint8_t*>(buffer), bytesRead, &insn);
    size_t limit = std::min(count, (size_t)5);
    for(size_t i = 0; i < limit; i++) {
        tui::printInstruction(insn[i], rip);
    }
    if(count > 0)
    {
        cs_free(insn, count);
    }
    if(count < 5) {
        std::cout << "** the address is out of the range of the text section." << std::endl;
    }
}

void Debugger::stepOneInstruction()
{
    bool breakPointHasHit = hitBreakpoint;
    uint64_t breakPointAddress = hitBreakpointAddress;
    hitBreakpoint = false;
    hitBreakpointAddress = 0;
    if(breakPointHasHit)
    {
        removeBreakpoint(breakPointAddress, false);
    }
    ptrace(PTRACE_SINGLESTEP, programLoader.getPid(), nullptr, nullptr);
    if(!waitStopAndParseSignal()) {
        std::cout << "** the target program terminated." << std::endl;
        programLoader.unload();
        elfParser.reset();
        isLoad = false;
        return;
    }
    uint64_t rip = getRegs().rip;
    auto it = breakpoints.find(rip);
    if(it != breakpoints.end())
    {
        hitBreakpointHandler(true);
    }
    Extract5Instructions();
    if(breakPointHasHit)
    {
        setBreakpoint(breakPointAddress, false);
    }
}

void Debugger::continueExecution()
{
    bool breakPointHasHit = hitBreakpoint;
    uint64_t breakPointAddress = hitBreakpointAddress;
    hitBreakpoint = false;
    hitBreakpointAddress = 0;
    if(breakPointHasHit)
    {
        removeBreakpoint(breakPointAddress, false);
    }
    ptrace(PTRACE_CONT, programLoader.getPid(), nullptr, nullptr);
    if(!waitStopAndParseSignal()) {
        std::cout << "** the target program terminated." << std::endl;
        programLoader.unload();
        elfParser.reset();
        isLoad = false;
        return;
    }
    Extract5Instructions();
    if(breakPointHasHit)
    {
        setBreakpoint(breakPointAddress, false);
    }
}

void Debugger::setBreakpoint(uint64_t p_address, bool p_addToMap)
{
    uint64_t start = elfParser.getTextSectionAddress();
    uint64_t end = start + elfParser.getTextSectionSize();
    if(p_address < start || p_address > end) {
        std::cerr << "Address out of text section" << std::endl;
        return;
    }
    long data = ptrace(PTRACE_PEEKTEXT, programLoader.getPid(), p_address, nullptr);
    if(data == -1) {
        std::cerr << "Failed to read memory" << std::endl;
        return;
    }
    uint64_t int3 = 0xcc;
    long newData = (data & ~0xff) | int3; // set the lowest byte to 0xcc
    long originalData = data & 0xff;
    if(ptrace(PTRACE_POKETEXT, programLoader.getPid(), p_address, newData) == -1) {
        std::cerr << "Failed to write memory" << std::endl;
        return;
    }
    if(p_addToMap)
    {
        breakpoints[p_address] = std::make_pair(originalData, breakPointCount);
        breakPointCount++;
        std::cout << "** set a breakpoint at 0x" << std::hex << p_address << std::dec << std::endl;
    }
}
void Debugger::removeBreakpoint(uint64_t p_address, bool p_removeFromMap)
{
    auto it = breakpoints.find(p_address);
    if(it == breakpoints.end()) {
        std::cerr << "Breakpoint not found" << std::endl;
        return;
    }
    long data = ptrace(PTRACE_PEEKTEXT, programLoader.getPid(), p_address, nullptr);
    if(data == -1) {
        std::cerr << "Failed to read memory" << std::endl;
        return;
    }
    long originalData = it->second.first;
    originalData = (data & ~0xff) | originalData; // restore the original data
    if(ptrace(PTRACE_POKETEXT, programLoader.getPid(), p_address, originalData) == -1) {
        std::cerr << "Failed to write memory" << std::endl;
        return;
    }
    if(p_removeFromMap)
    {
        breakpoints.erase(it);
    }
}
void Debugger::hitBreakpointHandler(bool p_beforeInstruction)
{
    auto regs = getRegs();
    hitBreakpoint = true;
    hitBreakpointAddress = regs.rip - 1; // rip point after the int3
    if(p_beforeInstruction)
    {
        hitBreakpointAddress += 1;
    }
    std::cout << "** breakpoint hit at 0x" << std::hex << hitBreakpointAddress << std::dec << std::endl;
    if(!p_beforeInstruction)
    {
        regs.rip -= 1; // rip point after the int3
        ptrace(PTRACE_SETREGS, programLoader.getPid(), nullptr, &regs);
    }
}
void Debugger::patchMemory(uint64_t p_address, uint64_t p_data)
{

}

void Debugger::showBreakpointsInfo()
{
    if(breakpoints.empty())
    {
        std::cout << "** no breakpoints." << std::endl;
        return;
    }
    std::vector<std::pair<uint64_t, uint64_t>> breakpointsInfo;
    for(auto it = breakpoints.begin(); it != breakpoints.end(); it++)
    {
        breakpointsInfo.push_back(std::make_pair(it->second.second, it->first));
    }
    std::sort(breakpointsInfo.begin(), breakpointsInfo.end());
    tui::printBreakpoint(breakpointsInfo);
}

cs_insn Debugger::getInstruction(uint64_t p_address)
{
    char buffer[16];
    size_t bytesRead = peekDataFromMemory(buffer, sizeof(buffer), p_address);
    if(bytesRead == 0) {
        std::cerr << "Failed to read memory" << std::endl;
        return cs_insn{};
    }
    cs_insn* insn;
    size_t count = disassembler.disassemble(reinterpret_cast<uint8_t*>(buffer), bytesRead, &insn);
    if(count == 0) {
        std::cerr << "Failed to disassemble" << std::endl;
        return cs_insn{};
    }
    cs_insn result = insn[0];
    cs_free(insn, count);
    return result;
}

void Debugger::run()
{
    if(isLoad)
    {
        Extract5Instructions();
    }
    std::cout << "(sdb)" << " ";
    while(true) {
        std::string userInput = waitUserInput();
        if(userInput == "quit") {
            break;
        }
        else if(userInput == "info reg")
        {
            if(isLoad)
            {
                tui::printRegisters(getRegs());
            }
            else
            {
                std::cout << "** please load a program first." << std::endl;
            }
        }
        else if(userInput == "si")
        {
            if(isLoad)
            {
                stepOneInstruction();
            }
            else
            {
                std::cout << "** please load a program first." << std::endl;
            }
        }
        else if(userInput.find("load ") == 0) // prefix is "load "
        {
            if(isLoad)
            {
                programLoader.unload();
                elfParser.reset();
                isLoad = false;
            }
            std::string program = userInput.substr(5);
            loadProgram(program.c_str());
            if(isLoad)
            {
                Extract5Instructions();
            }
        }
        else if(userInput.find("break ") == 0) // prefix is "b "
        {
            if(isLoad)
            {
                std::string address = userInput.substr(6);
                uint64_t breakpointAddress = std::stoull(address, nullptr, 16);
                setBreakpoint(breakpointAddress);
            }
            else
            {
                std::cout << "** please load a program first." << std::endl;
            }
        }
        else if(userInput == "cont")
        {
            if(isLoad)
            {
                continueExecution();
            }
            else
            {
                std::cout << "** please load a program first." << std::endl;
            }
        
        }
        else
        {
            std::cout << "** unknown command." << std::endl;
        }
        tui::printWithPrompt("");
    }

}