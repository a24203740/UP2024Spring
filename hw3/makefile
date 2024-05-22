CC = g++
CFLAGS = -I./ -no-pie

LDLIBS = -lcapstone
SRCDIR = ./src
SRC= $(wildcard ./src/*.cpp)
OBJ= $(SRC:.cpp=.o)

all: makeSRC sdb

makeSRC:
	$(MAKE) -C $(SRCDIR)

%.o: %.cpp
	$(CC) $< $(LDLIBS) $(CFLAGS) -c  -o $@

sdb: main.o $(OBJ)
	$(CC) $^ $(LDLIBS) -o $@

clear:
	rm -f *.o
	rm -f sdb
	$(MAKE) -C $(SRCDIR) clear

