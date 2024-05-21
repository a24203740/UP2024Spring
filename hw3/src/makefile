CC = g++
CFLAGS = -Wall -lcapstone -I../ 

SRC= $(wildcard *.cpp)
OBJ= $(SRC:.cpp=.o)
main: $(OBJ)

%.o: %.cpp
	$(CC) $< $(CFLAGS) -c -o $@

clear:
	rm -f $(OBJ)