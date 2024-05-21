#include "include/util.hpp"

void util::errquit(const char* msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

void util::checkError(int res, const char* msg) {
    if(res == -1) {
        errquit(msg);
    }
}

bool util::checkFileExistence(const char* file) {
    return access(file, F_OK) != -1; // Tests for the existence of the file.
}