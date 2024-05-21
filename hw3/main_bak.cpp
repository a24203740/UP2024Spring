
#include <iostream>
extern "C" {
    #include <capstone/capstone.h>
    #include <stdio.h>
    #include <inttypes.h>
    #include <elf.h>
};

const char* usage = "Usage: ./sdb [program]";

int main(int argc, char* argv[]) {
    if(argc > 2)
    {
        std::cout << usage << std::endl;
        return 1;
    }
    csh handle;
	cs_insn *insn;
	size_t count;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return -1;
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    // cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
    uint8_t CODE[100000];
    FILE* file = fopen(argv[1], "rb");
    if(file == NULL) {
        std::cout << "File not found" << std::endl;
        return 1;
    }
    size_t readsize = fread(CODE, 1, sizeof(CODE), file);
    fclose(file);
	count = cs_disasm(handle, CODE, readsize, 0x400000, 0, &insn);
	if (count > 0) {
		size_t j;
		for (j = 0; j < count; j++) {
			printf("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
					insn[j].op_str);
		}

		cs_free(insn, count);
	} else
		printf("ERROR: Failed to disassemble given code!\n");

	cs_close(&handle);

    return 0;


}