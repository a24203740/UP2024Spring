#include <iostream>
#include <stdio.h>
#include <inttypes.h>
#include <capstone/capstone.h>

#include "include/Debugger.hpp"

const char* usage = "Usage: ./sdb [program]";

int main(int argc, char* argv[]) {
    if(argc > 2)
    {
        std::cout << usage << std::endl;
        return 1;
    }

    Debugger debugger;
    if(argc == 2)
    {
        debugger.loadProgram(argv[1]);
    }
    debugger.run();


}