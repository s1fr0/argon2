uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')

CC=gcc

ifeq ($(uname_S),Darwin)
	CC=gcc-6
endif

IDIR=include
SRC=src
GDBFLAG=-ggdb
CFLAGS=-I$(IDIR) -fopenmp $(GDBFLAG) -Wall -O3

argon2: 
	$(CC) $(SRC)/*.c -o $@ $^ $(CFLAGS)

.PHONY: clean

clean:
	rm -rf argon2 argon2.dSYM