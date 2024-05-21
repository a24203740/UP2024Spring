#pragma once

#include <elf.h>
#include <string>
#include <tuple>
#include <iostream>
#include <fstream>
#include "include/util.hpp"

class ELFparser {
    public:
        ELFparser() = default;
        ~ELFparser() = default;
        void parse(const char* p_filename);
        uint64_t getEntryPoint() const { return entryPoint; }
        uint64_t getTextSectionOffset() const { return textSectionOffset; }
        uint64_t getTextSectionSize() const { return textSectionSize; }
        uint64_t getTextSectionAddress() const { return textSectionAddress; }
        void reset() { valid = false; }
        bool isValid() const { return valid; }
    private:
        bool valid{false};
        uint64_t entryPoint;
        uint64_t textSectionAddress;
        uint64_t textSectionOffset;
        uint64_t textSectionSize;

        /**
         * @param p_filename file to open
         * @param p_handler file handler will be stored here
         * @return true if file opened successfully, false otherwise
         */
        bool openFile(const char* p_filename, std::ifstream& p_handler);

        bool closeFile(std::ifstream& p_handler);

        bool isElf(std::ifstream& p_handler);

        /**
         * @brief Get the Section Header Info from the ELF file header
         * 
         * @param p_handler file handler to read from
         * @return {section header table offset, section header entry size, 
         * ,number of section headers, index of the section header string table}
         */
        std::tuple<uint64_t, uint16_t, uint16_t, uint16_t> getSectionHeaderInfo(std::ifstream& p_handler);

        bool findAndSetEntryPoint(std::ifstream& p_handler);
        bool findAndSetTextSection(uint64_t p_tableOffset, uint16_t p_entrySize, 
            uint16_t p_entryCount, uint16_t p_stringTableIndex, std::ifstream& p_handler);

};

