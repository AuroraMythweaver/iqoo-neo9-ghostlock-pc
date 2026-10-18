# GhostLock C CLI -- headless PC driver
#
#   make            build ./ghostlock
#   make test       offline test suite (mock adb, no device needed)
#   make static     single static binary (same output name + .static)
#   make install    PREFIX=/usr/local make install
#
CC      ?= cc
CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 -D_FILE_OFFSET_BITS=64 -Wall -Wextra -Wshadow -Wformat=2 \
           -Wstrict-prototypes -Wmissing-prototypes -Iinclude
LDFLAGS ?=
PREFIX  ?= /usr/local

SRC := $(wildcard src/*.c)
OBJ := $(SRC:.c=.o)
BIN := ghostlock

.PHONY: all clean test install static

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

src/%.o: src/%.c include/gl.h src/internal.h
	$(CC) $(CFLAGS) -c -o $@ $<

static:
	$(CC) $(CFLAGS) -static -o $(BIN) $(SRC) $(LDFLAGS)

test: $(BIN)
	./tests/run-tests.sh

install: $(BIN)
	install -Dm755 $(BIN) $(DESTDIR)$(PREFIX)/bin/ghostlock

clean:
	rm -f $(OBJ) $(BIN)
