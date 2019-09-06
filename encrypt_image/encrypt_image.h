#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>

/* OpenSSL includes*/
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define MAX_SIZE         0xFFFFF
#define TEST             0
#define BASE_HEX         16

#define AES_KEY_SIZE     16
#define CTR_SIZE         8
#define CTR_EXT_SIZE     16
#define IMG_START_OFFSET 4096
#define IMG_HDR_SIZE     IMG_START_OFFSET
#define SYS_ADDR_OFFSET  12
#define MX7ULP_QSPI_BASE_ADDR   0xC0000000

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

#define SWAP32(a, b)    do{unsigned int tmp; tmp=a; a=b; b=tmp;}while(0)

/************************
	Command line arguments
************************/
/* Valid short command line option letters. */
const char* const short_opt = "i:k:c:s:e:o:h";

/* Valid long command line options. */
const struct option long_opt[] =
{
	{"input-image", required_argument, 0, 'i'},
	{"enc-key", required_argument,  0, 'k'},
	{"counter", required_argument,  0, 'c'},
	{"start-address", required_argument,  0, 's'},
	{"end-address", required_argument, 0, 'e'},
	{"output", required_argument,  0, 'o'},
	{"help", no_argument, 0, 'h'},
	{NULL, 0, NULL, 0}
};

/* Option descriptions */
const char* opt_desc[] =
{
	"Input image to be decrypted",
	"Input image encryption key (128-bit)",
	"Input counter (64 bit)",
	"Start Address of encryption in File (32-bit)",
	"End Address of encryption in File (32-bit)",
	"Output File",
	"This text",
	NULL
};

/*********************************
	Globals
 ********************************/

uint8_t qspi_base_addr[4] = "\xC0\x00\x00\x00";

static const unsigned char test_key[16] =
{
	0x00, 0x01, 0x02, 0x03, // key_w0
	0x04, 0x05, 0x06, 0x07, // key_w1
	0x08, 0x09, 0x0a, 0x0b, // key_w2
	0x0c, 0x0d, 0x0e, 0x0f, // key_w3
};

static unsigned char test_ctr[16] =
{
	0x01, 0x23, 0x45, 0x67, // ctr_w0
	0x89, 0xab, 0xcd, 0xef, // ctr_w1
	0x88, 0x88, 0x88, 0x88, // XOR(ctr_w0, ctr_w1)
	0xC0, 0x00, 0x10, 0x00, //systemAddress [31...4],0000h + 0x1000 offset
};
