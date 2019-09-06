#
# Copyright 2019 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
#

# Makefile for key_scrambler tool

CC = gcc

COPTS = -g -Wall -Werror
CFLAGS = -I.

DEPS = key_scrambler.h
SRCS = key_scrambler.c

.PHONY: all clean

ifeq ($(DEBUG), 1)
CFLAGS += -D DEBUG
endif

all: key_scrambler

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(COPTS) $(CFLAGS)

key_scrambler: key_scrambler.c
	@echo "Building key_scrambler tool.."
	$(CC) $(COPTS) $(CFLAGS) -o $@ $(SRCS) $(CRYPTO_LIBS)
	@echo "done"

clean:
	rm -rvf key_scrambler *.o
