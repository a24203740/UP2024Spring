#pragma once

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

namespace util {
    void errquit(const char* msg);
    void checkError(int res, const char* msg);
    bool checkFileExistence(const char* file);
} // namespace util