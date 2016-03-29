CC = gcc
CFLAGS = -Wall -Werror -DCOLOR
BIN = pbproxy
LIBS = -lcrypto -lssl
SRC = $(wildcard *.c)

.PHONY: all debug clean help check

all: $(BIN) ## Generates all programs that this makefile can generate.

debug: CFLAGS += -g -DDEBUG
debug: $(BIN) ## Generates a binary with debugging symbols and debug print statements.

pbproxy: $(SRC) ## Generates the pbproxy program.
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

clean: ## Removes all source binaries and object files.
	rm -f $(BIN) *.o

help: ## Generates this help menu.
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

BADFUNCS='[^_.>a-zA-Z0-9](str(n?cpy|n?cat|xfrm|n?dup|str|pbrk|tok|_)|stpn?cpy|a?sn?printf|byte_)'
check: ## Checks program for bad functions.
	@echo Files with potentially dangerous functions.
	@egrep -Hn $(BADFUNCS) $(SRC) || true
