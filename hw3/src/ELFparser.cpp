#include "include/ELFparser.hpp"
#include <string.h>
bool ELFparser::openFile(const char* p_filename, std::ifstream& p_file)
{
    if(!util::checkFileExistence(p_filename)) {
        std::cerr << "File does not exist: " << p_filename << std::endl;
        valid = false;
        return false;
    }
    p_file.open(p_filename, std::ios::binary); // read-only
    if(!p_file.is_open()) {
        std::cerr << "Could not open file: " << p_filename << std::endl;
        valid = false;
        return false;
    }
    return true;
}

bool ELFparser::closeFile(std::ifstream& p_file)
{
    if(p_file.is_open()) {
        p_file.close();
        return true;
    }
    return false;
}

bool ELFparser::isElf(std::ifstream& p_file)
{
    char e_ident[EI_NIDENT];
    p_file.seekg(0, std::ios::beg);
    p_file.read(e_ident, EI_NIDENT);
    // 0x7F 'E' 'L' 'F'
    if(e_ident[EI_MAG0] != ELFMAG0 || e_ident[EI_MAG1] != ELFMAG1 || e_ident[EI_MAG2] != ELFMAG2 || e_ident[EI_MAG3] != ELFMAG3) {
        std::cerr << "Not an ELF file" << std::endl;
        valid = false;
        return false;
    }
    return true;
}

std::tuple<uint64_t, uint16_t, uint16_t, uint16_t> ELFparser::getSectionHeaderInfo(std::ifstream& p_handler)
{
    Elf64_Ehdr elfHeader;
    p_handler.seekg(0, std::ios::beg);
    p_handler.read(reinterpret_cast<char*>(&elfHeader), sizeof(Elf64_Ehdr));
    return {elfHeader.e_shoff, elfHeader.e_shentsize, elfHeader.e_shnum, elfHeader.e_shstrndx};

}

bool ELFparser::findAndSetEntryPoint(std::ifstream& p_handler)
{
    Elf64_Ehdr elfHeader;
    p_handler.seekg(0, std::ios::beg);
    p_handler.read(reinterpret_cast<char*>(&elfHeader), sizeof(Elf64_Ehdr));
    entryPoint = elfHeader.e_entry;
    return true;
}
bool ELFparser::findAndSetTextSection(uint64_t p_tableOffset, uint16_t p_entrySize, uint16_t p_entryCount, uint16_t p_stringTableIndex, std::ifstream& p_handler)
{
    Elf64_Shdr sectionHeader;

    char sectionStringTable[100000];
    char sectionName[100];
    p_handler.seekg(p_tableOffset + p_stringTableIndex * p_entrySize);
    p_handler.read(reinterpret_cast<char*>(&sectionHeader), sizeof(Elf64_Shdr));
    p_handler.seekg(sectionHeader.sh_offset); // Seek to the string table offset
    p_handler.read(sectionStringTable, sectionHeader.sh_size);

    for(int i = 0; i < p_entryCount; i++) {
        p_handler.seekg(p_tableOffset + i * p_entrySize);
        p_handler.read(reinterpret_cast<char*>(&sectionHeader), sizeof(Elf64_Shdr));
        strncpy(sectionName, sectionStringTable + sectionHeader.sh_name, sizeof(sectionName) - 1);
        sectionName[sizeof(sectionName) - 1] = '\0';
        if(strcmp(sectionName, ".text") == 0) {
            textSectionOffset = sectionHeader.sh_offset;
            textSectionSize = sectionHeader.sh_size;
            textSectionAddress = sectionHeader.sh_addr;
            return true;
            break;
        }
    }
    return false;
}


void ELFparser::parse(const char* p_filename)
{
    valid = false;
    std::ifstream handler;
    if(!openFile(p_filename, handler)) {
        return;
    }
    if(!isElf(handler)) {
        closeFile(handler);
        return;
    }
    auto [sectionHeaderTableOffset, sectionHeaderEntrySize, 
            sectionHeaderCount, sectionHeaderStringTableIndex] = getSectionHeaderInfo(handler);

    bool res = findAndSetEntryPoint(handler);
    if(!res) {
        closeFile(handler);
        return;
    }
    res = findAndSetTextSection(sectionHeaderTableOffset, sectionHeaderEntrySize, 
            sectionHeaderCount, sectionHeaderStringTableIndex, handler);
    if(!res) {
        closeFile(handler);
        return;
    }
    valid = true;
}