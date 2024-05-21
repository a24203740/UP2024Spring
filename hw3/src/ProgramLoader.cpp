#include "include/ProgramLoader.hpp"

/* ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data) */

ProgramLoader::ProgramLoader(const char* p_program) {
    setProgram(p_program);
}

void ProgramLoader::setProgram(const char* p_program) {
    program = p_program;
    progIsValid = util::checkFileExistence(program);
}

bool ProgramLoader::isProcessAlive() {
    if(kill(pid, 0) == 0) { // send signal 0 to check if process is alive
        return true;
    }
    else if(errno == ESRCH) {
        return false; // pid not found, process is not alive
    }
    else {
        util::checkError(-1, "kill");
    }
    return false;
}

void ProgramLoader::unload() {
    if(progIsLoaded) {
        if(isProcessAlive()) {
            kill(pid, SIGKILL);
            ptrace(PTRACE_DETACH, pid, NULL, NULL);
        }
    }
    progIsLoaded = false;
}

/**
 * @brief load program, must be called after setProgram or constructor with program
 * 
 * @return pid of traced program
 */
int ProgramLoader::load() {
    if(!progIsValid) {
        return -1;
    }
    pid = fork();
    if(pid == 0) {
        personality(ADDR_NO_RANDOMIZE);
        ptrace(PTRACE_TRACEME, 0, NULL, NULL); // pid, addr, data is ignored
        util::checkError(
            execl(program, program, NULL), "execl"); 
    }
    else
    {
        int status;
        util::checkError(waitpid(pid, &status, 0), "waitpid");
        assert(WIFSTOPPED(status));
        ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_EXITKILL);
    }
    progIsLoaded = true;
    return pid;
}

pid_t ProgramLoader::getPid() {
    if(!progIsLoaded) {
        return -1;
    }
    return pid;
}
