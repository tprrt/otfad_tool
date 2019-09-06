#ifndef KEY_SCRAMBLER_H
#define KEY_SCRAMBLER_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>


#define OTFAD_KEY_SIZE          16
#define KEY_SCRAMBLE_SIZE       4
#define KEY_SCRAMBLE_ALIGN_MASK 0xFF
#define BASE_HEX                16
#define NUM_CONTEXT             4

#define FREE(x)         do { \
				if(x != NULL) { \
					free(x); \
					x = NULL; \
				} \
			} while(0)

#define FCLOSE(x)         do { \
				if(x != NULL) { \
					fclose(x); \
					x = NULL; \
				} \
			} while(0)

#define BIT_REVERSE8(x) do {   \
				x = ((x & 0x55) << 1) | ((x & 0xAA) >> 1);  \
				x = ((x & 0x33) << 2) | ((x & 0xCC) >> 2);  \
				x = ((x & 0x0F) << 4) | ((x & 0xF0) >> 4);  \
			 } while(0)

/************************
	Command line arguments
************************/
/* Valid short command line option letters. */
const char* const short_opt = "i:k:a:c:o:h";
/* Valid long command line options. */
const struct option long_opt[] =
{
	{"otfad-key", required_argument, 0, 'i'},
	{"key-scramble", required_argument, 0, 'k'},
	{"key-scramble-align", required_argument, 0, 'a'},
	{"context", required_argument, 0, 'c'},
	{"output", required_argument,  0, 'o'},
	{"help", no_argument, 0, 'h'},
	{NULL, 0, NULL, 0}
};

/* Option descriptions */
const char* opt_desc[] =
{
	"Input OTFAD key (128-bit)",
	"Input Scrambled key (32-bit)",
	"Input Key Align (8-bit)",
	"Output File",
	"This text",
	NULL
};

unsigned char *do_aes128_key_wrap(unsigned char *, unsigned char *);

/* OTFAD Key to be burned in Fuse */
static const unsigned char test_otfad_key[OTFAD_KEY_SIZE] =
{
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};

static const unsigned char test_key_scramble[KEY_SCRAMBLE_SIZE] =
{
	0x11, 0x11, 0x11, 0x11
};

static const uint8_t test_key_scramble_align = 0xE4; // 0b11_10_01_00

#endif /* KEY_SCRAMBLER_H */
