#pragma once

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/personality.h>
#include <sys/wait.h>
#include <assert.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include "include/util.hpp"


class ProgramLoader {
    public:
        ProgramLoader() : program(nullptr), pid(0), progIsValid(false), progIsLoaded(false) {};
        ProgramLoader(const char* p_program);
        ~ProgramLoader();
        void setProgram(const char* p_program);
        int load();
        void unload();
        pid_t getPid();
        bool isValid() const { return progIsValid; }
    private:
        const char* program;
        pid_t pid;
        bool progIsValid;
        bool progIsLoaded;
        bool isProcessAlive();

};