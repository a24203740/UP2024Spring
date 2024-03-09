obj-m     += maze.o
ccflags-y += -DEXPORT_SYMTAB

all: mymazetest
	make -C ../dist/modulebuild M=$(PWD) modules

mymazetest: mymazetest.c
	$(CROSS_COMPILE)gcc -o $@ $< -Wall -static

clean:
	rm -f mymazetest
	make -C ../dist/modulebuild M=$(PWD) clean

install: all
	mkdir -p ../rootfs/modules
	cp mymazetest maze.ko ../rootfs/modules
