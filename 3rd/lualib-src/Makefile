include ../../platform.mk

LUACLIB_DIR = ../../luaclib

LUACLIB_NAMES = lfs lunix

LUA_INC ?= ../lua
CFLAGS = -g -O2 -Wall -I$(LUA_INC) $(MYCFLAGS)

ALL_LIBS = $(foreach v, $(LUACLIB_NAMES), $(LUACLIB_DIR)/$(v).so)

all: $(ALL_LIBS)

$(LUACLIB_DIR)/lfs.so: lfs.c | $(LUACLIB_DIR)
	$(CC) $(CFLAGS) $(SHARED) $^ -o $@

$(LUACLIB_DIR)/lunix.so: lunix.c | $(LUACLIB_DIR)
	$(CC) $(CFLAGS) $(SHARED) $^ -o $@

clean:
	rm -rf $(ALL_LIBS)

.PHONY: clean
