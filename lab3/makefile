# Makefile template for a shared library in C
# https://www.topbug.net/blog/2019/10/28/makefile-template-for-a-shared-library-in-c-with-explanations/
# https://medium.com/fcamels-notes/linux-%E7%B7%A8%E8%AD%AF-shared-library-%E7%9A%84%E6%96%B9%E6%B3%95%E5%92%8C%E6%B3%A8%E6%84%8F%E4%BA%8B%E9%A0%85-cb35844ef331

CC = gcc  # C compiler
CFLAGS = -fPIC -Wall -Wextra -O2 -g -c  # C flags
LDFLAGS = -shared   # linking flags
RM = rm -f   # rm command
TARGET_LIB = libtarget.so  # target lib

.PHONY: all solve clean

all: maze

solve: libsolver.so

libsolver.so: libsolver.o
	$(CC) $(LDFLAGS) $^ -o $@

libsolver.o: libsolver.c
	$(CC) $(CFLAGS) $<

libmaze.so: libmaze_dummy.o
	$(CC) $(LDFLAGS) $^ -o $@ 

libmaze_dummy.o: libmaze_dummy.c
	$(CC) $(CFLAGS) $<

maze: maze.c libmaze.so
# L.: ask the linker to look for the library in the current directory
	$(CC) -g $< -o $@ -L. -lmaze 

clean:
	$(RM) *.o *.so maze