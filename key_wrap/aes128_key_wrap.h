/*
 * Copyright 2019 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef KEY_WRAP_H

/* OpenSSL includes*/
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define AES_KEY_SIZE            16
#define MAX_PT_SIZE             40
#define MAX_CT_SIZE             48

#endif /* KEY_WRAP_H */

void handle_cipher_err(void);
unsigned char *aes128_key_wrap(unsigned char *pt, unsigned char *iv, unsigned char *kek);
