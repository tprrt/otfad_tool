#
# Copyright 2019 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
#

# Makefile for encrypt_image tool

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
DEPS = encrypt_image.h
SRCS = encrypt_image.c

# Phony targets
.PHONY: all clean

# Debug flag
ifeq ($(DEBUG), 1)
CFLAGS += -D DEBUG
endif

# Build target
all: encrypt_image

# Object files
%.o: %.c $(DEPS)
	$(TARGET_CC) -c -o $@ $< $(COPTS) $(CFLAGS)

# Final executable
encrypt_image: encrypt_image.c
	@echo "Building encrypt_image tool.."
	$(TARGET_CC) $(COPTS) $(CFLAGS) -o $@ $(SRCS) $(LDFLAGS) $(CRYPTO_LIBS)
	@echo "done"

# Clean
clean:
	rm -rvf encrypt_image *.o
