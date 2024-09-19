#
# Copyright 2019 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
#

# Makefile for key_wrap tool

# Compiler settings
CC ?= gcc

# Cross-compiler settings
CROSS_COMPILE ?=
TARGET_CC = $(CROSS_COMPILE)$(CC)

# Compiler and linker flags
COPTS ?= -g -Wall -Werror
CFLAGS ?= -I.
LDFLAGS ?=
CRYPTO_LIBS ?= -lssl -lcrypto

# Source files and dependencies
DEPS = key_wrap.h compute_crc32.h aes128_key_wrap.h
SRCS = key_wrap.c compute_crc32.c aes128_key_wrap.c
OBJS = $(SRCS:.c=.o)

# Phony targets
.PHONY: all clean

# Debug flag
ifeq ($(DEBUG), 1)
CFLAGS += -D DEBUG
endif

# Build target
all: key_wrap

# Object files
%.o: %.c
	$(TARGET_CC) -c -o $@ $< $(COPTS) $(CFLAGS)

# Final executable
key_wrap: $(OBJS)
	@echo "Building key_wrap tool.."
	$(TARGET_CC) $(COPTS) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS) $(CRYPTO_LIBS)
	@echo "done"

# Clean
clean:
	rm -rvf key_wrap *.o
