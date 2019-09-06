#
# Copyright 2019 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
#

# Makefile for key_wrap tool

CC = gcc

COPTS = -g -Wall -Werror
CFLAGS = -I.
CRYPTO_LIBS = -lssl -lcrypto

DEPS = key_wrap.h compute_crc32.h aes128_key_wrap.h
SRCS = key_wrap.c compute_crc32.c aes128_key_wrap.c

.PHONY: all clean

ifeq ($(DEBUG), 1)
CFLAGS += -D DEBUG
endif

all: key_wrap

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(COPTS) $(CFLAGS)

key_wrap: key_wrap.c
	@echo "Building key_wrap tool.."
	$(CC) $(COPTS) $(CFLAGS) -o $@ $(SRCS) $(CRYPTO_LIBS)
	@echo "done"

clean:
	rm -rvf key_wrap *.o
