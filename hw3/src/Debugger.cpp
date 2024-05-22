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
    isLoad = false;
    hitBreakpoint = false;
    hitBreakpointAddress = 0;
    breakPointCount = 0;
    breakpoints.clear();
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
        siginfo_t info;
        ptrace(PTRACE_GETSIGINFO, programLoader.getPid(), nullptr, &info); // Retrieve information about the signal that caused the stop
        if(info.si_signo != SIGTRAP) {
            std::cerr << "Unexpected signal" << std::endl;
            return false;
        }
        switch (info.si_code)
        {
        case TRAP_TRACE:
            // stop because PTRACE_SINGLESTEP normally
            return true;
        case TRAP_BRKPT: // stop because PTRACE_SINGLESTEP excute syscall
            return true;
        case SI_KERNEL: // stop because excute int3
            hitBreakpointHandler();
            return true;
        default:
            std::cerr << "Unexpected signal code" << std::endl;
            break;
        }
    }
    else if(WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80))
    {
        if(eventSyscall == 0)
        {
            syscallNumber = getRegs().orig_rax;
            eventSyscall = 1;
        }
        else if(eventSyscall == 1)
        {
            eventSyscall = 2;
        }
        return true;
    }
    else if(WIFEXITED(status))
    {
        return false;
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

void Debugger::Extract5Instructions(uint64_t p_address)
{
    if(p_address == 1e18) // default value
    {
        p_address = getRegs().rip;
    }
    char buffer[96]; // instructions are at most 15 bytes long, 5 instructions = 75 bytes, 96 is enough
    size_t bytesRead = peekDataFromMemory(buffer, sizeof(buffer), p_address);
    if(bytesRead == 0) {
        std::cerr << "Failed to read memory" << std::endl;
        return;
    }
    for(size_t i = 0; i < bytesRead; i++)
    {
        auto it = breakpoints.find(p_address + i);
        if(it != breakpoints.end())
        {
            buffer[i] = it->second.first; // restore the original data
        }
    }
    cs_insn* insn;
    size_t count = 0;
    count = disassembler.disassemble(reinterpret_cast<uint8_t*>(buffer), bytesRead, &insn, p_address);
    size_t limit = std::min(count, (size_t)5);
    for(size_t i = 0; i < limit; i++) {
        tui::printInstruction(insn[i], p_address);
    }
    if(count > 0)
    {
        cs_free(insn, count);
    }
    if(count < 5) {
        std::cout << "** the address is out of the range of the text section." << std::endl;
    }
}

bool Debugger::stepOneInstruction()
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
        return true;
    }
    uint64_t rip = getRegs().rip;
    auto it = breakpoints.find(rip);
    if(it != breakpoints.end())
    {
        hitBreakpointHandler(true);
        std::cout << "** hit a breakpoint at 0x" << std::hex << hitBreakpointAddress << "." << std::dec << std::endl;
    }
    if(breakPointHasHit)
    {
        setBreakpoint(breakPointAddress, false);
    }
    return false;
}

bool Debugger::continueExecution(bool stopAtSyscall)
{
    if(hitBreakpoint)
    {
        // removeBreakpoint(breakPointAddress, false);
        bool terminated = stepOneInstruction(); // remove breakpoint and step one instruction and then set back breakpoint
        if(terminated)
        {
            return true;
        }
        if(hitBreakpoint) // if hit breakpoint again, return
        {
            return false;
        }
    }
    if(stopAtSyscall)
    {
        ptrace(PTRACE_SYSCALL, programLoader.getPid(), nullptr, nullptr);
    }
    else
    {
        ptrace(PTRACE_CONT, programLoader.getPid(), nullptr, nullptr);
    }
    if(!waitStopAndParseSignal()) {
        std::cout << "** the target program terminated." << std::endl;
        programLoader.unload();
        elfParser.reset();
        isLoad = false;
        return true;
    }
    if(hitBreakpoint)
    {
        std::cout << "** hit a breakpoint at 0x" << std::hex << hitBreakpointAddress << "." << std::dec << std::endl;
    }
    return false;
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
    if(p_address == getRegs().rip)
    {
        hitBreakpointHandler(true);
    }
    if(p_addToMap)
    {
        breakpoints[p_address] = std::make_pair(originalData, breakPointCount);
        breakPointCount++;
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
    if(!p_beforeInstruction)
    {
        regs.rip -= 1; // rip point after the int3
        ptrace(PTRACE_SETREGS, programLoader.getPid(), nullptr, &regs);
    }
}
void Debugger::patchMemory(uint64_t p_address, uint64_t p_data, uint64_t len)
{
    auto getNthByteOfData = [](uint64_t p_data, size_t p_n) -> uint8_t {
        return (p_data >> (p_n * 8)) & 0xff;
    };
    if(len != 1 && len != 2 && len != 4 && len != 8)
    {
        std::cerr << "Invalid length" << std::endl;
        return;
    }
    long data = ptrace(PTRACE_PEEKTEXT, programLoader.getPid(), p_address, nullptr);
    if(data == -1) {
        std::cerr << "Failed to read memory" << std::endl;
        return;
    }
    long mask = 0;
    for(size_t i = 0; i < len; i++)
    {
        mask |= (long)0xff << (i * 8); // set 0 - (len*8-1) bits to 1 => set the lowest len bytes to 0xff
    }
    long newData = (data & ~mask); // reset the lowest len bytes to 0
    newData |= (p_data & mask); // set the lowest len bytes to p_data
    if(ptrace(PTRACE_POKETEXT, programLoader.getPid(), p_address, newData) == -1) {
        std::cerr << "Failed to write memory" << std::endl;
        return;
    }
    for(auto it = breakpoints.begin(); it != breakpoints.end(); it++)
    {
        if(it->first >= p_address && it->first < p_address + len)
        {
            uint64_t offset = it->first - p_address;
            it->second.first = getNthByteOfData(p_data, offset); // update the original data
            setBreakpoint(it->first); // set the breakpoint again
        }
    }
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

int64_t Debugger::findBreakpointAddrByIndex(uint64_t p_index)
{
    for(auto it = breakpoints.begin(); it != breakpoints.end(); it++)
    {
        if(it->second.second == p_index)
        {
            return it->first;
        }
    }
    return -1;
}

void Debugger::run()
{
    if(isLoad)
    {
        Extract5Instructions();
    }
    while(true) {
        tui::printWithPrompt("");
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
                bool terminated = stepOneInstruction();
                if(!terminated)
                {
                    Extract5Instructions();
                }
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
                std::cout << "** set a breakpoint at 0x" << std::hex << breakpointAddress << "." << std::dec << std::endl;
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
                bool terminated = continueExecution(false);
                if(!terminated)
                {
                    Extract5Instructions();
                }
            }
            else
            {
                std::cout << "** please load a program first." << std::endl;
            }
        }
        else if(userInput == "info break")
        {
            if(isLoad)
            {
                showBreakpointsInfo();
            }
            else
            {
                std::cout << "** please load a program first." << std::endl;
            }
        }
        else if(userInput.find("delete ") == 0) // prefix is "delete "
        {
            if(isLoad)
            {
                std::string index = userInput.substr(7);
                uint64_t breakpointIndex = std::stoull(index, nullptr, 10);
                int64_t breakpointAddress = findBreakpointAddrByIndex(breakpointIndex);
                if(breakpointAddress != -1)
                {
                    removeBreakpoint((uint64_t)breakpointAddress);
                    std::cout << "** delete breakpoint " << breakpointIndex << "." << std::endl;
                    if((uint64_t)breakpointAddress == hitBreakpointAddress)
                    {
                        hitBreakpoint = false;
                        hitBreakpointAddress = 0;
                    }
                }
                else
                {
                    std::cout << "** breakpoint " << index << " does not exist." << std::endl;
                }
            }
            else
            {
                std::cout << "** please load a program first." << std::endl;
            }
        }
        else if(userInput.find("patch ") == 0) // prefix is "patch "
        {
            if(isLoad)
            {
                std::string address = userInput.substr(6);
                size_t spacePos = address.find(" ");
                if(spacePos == std::string::npos)
                {
                    std::cerr << "Invalid input" << std::endl;
                    continue;
                }
                std::string data = address.substr(spacePos + 1);
                address = address.substr(0, spacePos);
                spacePos = data.find(" ");
                if(spacePos == std::string::npos)
                {
                    std::cerr << "Invalid input" << std::endl;
                    continue;
                }
                std::string len = data.substr(spacePos + 1);
                data = data.substr(0, spacePos);
                uint64_t patchAddress = std::stoull(address, nullptr, 16);
                uint64_t patchData = std::stoull(data, nullptr, 16);
                uint64_t patchLen = std::stoull(len, nullptr, 10);
                patchMemory(patchAddress, patchData, patchLen);
                std::cout << "** patch memory at address 0x" << std::hex << patchAddress <<  "." << std::endl;
            }
            else
            {
                std::cout << "** please load a program first." << std::endl;
            }
        }
        else if(userInput == "syscall")
        {
            if(isLoad)
            {
                // eventSyscall = 0; no event
                // eventSyscall = 1; enter syscall
                // eventSyscall = 2; leave syscall
                if(eventSyscall == 2)
                {
                    syscallNumber = 0;
                    eventSyscall = 0; // reset Leave Syscall to no event
                }
                bool terminated = continueExecution(true);
                if(terminated)
                {
                    continue;
                }
                if(eventSyscall != 0)
                {
                    uint64_t addr = getRegs().rip - 2;
                    if(eventSyscall == 1)
                    {
                        std::cout << "** enter a syscall(" << syscallNumber << ") at 0x" << std::hex << addr << "." << std::dec << std::endl;
                    }
                    else if(eventSyscall == 2)
                    {
                        std::cout << "** leave a syscall(" << syscallNumber << ") = " << getRegs().rax <<  " at 0x" << std::hex << addr << "." << std::dec << std::endl;
                    }
                    Extract5Instructions(addr);
                }
                else 
                {
                    Extract5Instructions();
                }
            
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
    }

}