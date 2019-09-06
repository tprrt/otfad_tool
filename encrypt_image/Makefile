#
# Copyright 2019 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
#

# Makefile for encrypt_image tool 

CC = gcc

COPTS = -g -Wall -Werror
CFLAGS = -I.
CRYPTO_LIBS = -lssl -lcrypto

DEPS = encrypt_image.h
SRCS = encrypt_image.c

.PHONY: all clean

ifeq ($(DEBUG), 1)
CFLAGS += -D DEBUG
endif

all: encrypt_image

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(COPTS) $(CFLAGS)

encrypt_image: encrypt_image.c
	@echo "Building encrypt_image tool.."
	$(CC) $(COPTS) $(CFLAGS) -o $@ $(SRCS) $(CRYPTO_LIBS)
	@echo "done"

clean:
	rm -rvf encrypt_image *.o
