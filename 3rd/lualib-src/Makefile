include ../../platform.mk

LUACLIB_DIR = ../../luaclib

LUACLIB_NAMES = lfs lunix lrc4 laoi ltrace

LUA_INC ?= ../lua
CFLAGS = -g -O0 -Wall -I$(LUA_INC) $(MYCFLAGS)

ALL_LIBS = $(foreach v, $(LUACLIB_NAMES), $(LUACLIB_DIR)/$(v).so)

all: $(ALL_LIBS)

$(LUACLIB_DIR)/lfs.so: lfs.c | $(LUACLIB_DIR)
	$(CC) $(CFLAGS) $(SHARED) $^ -o $@

$(LUACLIB_DIR)/lunix.so: lunix.c | $(LUACLIB_DIR)
	$(CC) $(CFLAGS) $(SHARED) $^ -o $@

$(LUACLIB_DIR)/lrc4.so: rc4/lrc4.c rc4/rc4.c | $(LUACLIB_DIR)
	$(CC) $(CFLAGS) $(SHARED) $^ -o $@

$(LUACLIB_DIR)/laoi.so: aoi/laoi.c aoi/aoi.c | $(LUACLIB_DIR)
	$(CC) $(CFLAGS) $(SHARED) $^ -o $@

$(LUACLIB_DIR)/ltrace.so: ltrace.c | $(LUACLIB_DIR)
	$(CC) $(CFLAGS) $(SHARED) $^ -o $@

clean:
	rm -rf $(ALL_LIBS)

.PHONY: clean
