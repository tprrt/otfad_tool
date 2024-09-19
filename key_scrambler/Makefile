#
# Copyright 2019 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
#

# Makefile for key_scrambler tool

# Compiler settings
CC ?= gcc

# Cross-compiler settings
CROSS_COMPILE ?=
TARGET_CC = $(CROSS_COMPILE)$(CC)

# Compiler and linker flags
COPTS ?= -g -Wall -Werror
CFLAGS ?= -I.
LDFLAGS ?=

# Source files and dependencies
DEPS = key_scrambler.h
SRCS = key_scrambler.c
OBJS = $(SRCS:.c=.o)

# Phony targets
.PHONY: all clean

# Debug flag
ifeq ($(DEBUG), 1)
CFLAGS += -D DEBUG
endif

# Build target
all: key_scrambler

# Object files
%.o: %.c $(DEPS)
	$(TARGET_CC) -c -o $@ $< $(COPTS) $(CFLAGS)

# Final executable
key_scrambler: $(OBJS)
	@echo "Building key_scrambler tool.."
	$(TARGET_CC) $(COPTS) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)
	@echo "done"

# Clean
clean:
	rm -rvf key_scrambler *.o
