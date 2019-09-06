#ifndef KEY_WRAP_H
#define KEY_WRAP_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

/* OpenSSL includes*/
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define OTFAD_KEY_SIZE          16
#define AES_KEY_SIZE            16
#define IV_SIZE                 8
#define CTR_SIZE                8
#define MAX_PT_SIZE             40
#define MAX_CT_SIZE             48
#define PAD_SIZE                16
#define CRC32_FILLER            0x00000000
#define BASE_HEX                16
// #define NUM_CONTEXT             4

/* Region descriptor defines */
#define CTX_RGD_W_RO_SHIFT      2
#define CTX_RGD_W_ADE_SHIFT     1
#define CTX_RGD_W_VLD_SHIFT     0
#define RO                      0x0 << CTX_RGD_W_RO_SHIFT
#define ADE                     0x1 << CTX_RGD_W_ADE_SHIFT
#define SRT_ADDR_MASK           0xFFFFFC00
#define END_ADDR_MASK           0xFFFFFFF8
#define END_ADDR_RSVD           0x3F8

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
const char* const short_opt = "i:k:c:s:e:vo:h";
/* Valid long command line options. */
const struct option long_opt[] =
{
        {"otfad-key", required_argument, 0, 'i'},
        {"enc-key", required_argument,  0, 'k'},
        {"counter", required_argument,  0, 'c'},
        {"start-address", required_argument,  0, 's'},
        {"end-address", required_argument, 0, 'e'},
        {"is-valid", no_argument, 0, 'v'},
        {"output", required_argument,  0, 'o'},
        {"help", no_argument, 0, 'h'},
        {NULL, 0, NULL, 0}
};

/* Option descriptions */
const char* opt_desc[] =
{
        "Input OTFAD key (128-bit)",
        "Input Image Encryption Key (128-bit)",
        "Input counter (64-bit)",
        "Start address (32-bit)",
        "End address (32-bit)",
        "Valid bit",
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

/* IV is constant as per RFC3394 */
static unsigned char iv[IV_SIZE] = {
        0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6
};

static const unsigned char test_pt[MAX_PT_SIZE] =
{
        0x00, 0x01, 0x02, 0x03, // key_w0
        0x04, 0x05, 0x06, 0x07, // key_w1
        0x08, 0x09, 0x0a, 0x0b, // key_w2
        0x0c, 0x0d, 0x0e, 0x0f, // key_w3
        0x01, 0x23, 0x45, 0x67, // ctr_w0
        0x89, 0xab, 0xcd, 0xef, // ctr_w1
        0x00, 0x00, 0x00, 0xC0, // rgd_w0 <-- start_addr
        0xFB, 0xFF, 0x00, 0xCF, // rgd_w1 <-- end_addr + AES decryption enabled + valid context
        0x00, 0x00, 0x00, 0x00, // crc_w0
        0xB6, 0x95, 0x92, 0x9f  // crc_w1
};

#endif /* KEY_WRAP_H */
