CC=gcc
CFLAGS=-Iinclude -Wall -Wextra -g
LDFLAGS=-lpcap
SRC=$(wildcard src/*.c)
OBJ=$(SRC:.c=.o)
EXEC=netanalyzer

all: $(EXEC)

$(EXEC): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(EXEC) src/*.o
