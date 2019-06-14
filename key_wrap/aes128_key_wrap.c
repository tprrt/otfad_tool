#include "aes128_key_wrap.h"

void handle_cipher_err(void)
{
	ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
}

unsigned char *aes128_key_wrap(unsigned char *pt, unsigned char *iv, unsigned char *kek)
{
	EVP_CIPHER_CTX *ctx;
	unsigned char temp_in_pt[16]; // 128‐bit temporary plaintext input vector
	static unsigned char ciphertext[MAX_CT_SIZE];
	unsigned char int_chk[8]; // 64‐bit integrity check register
	unsigned char temp_out_ct[AES_KEY_SIZE]; // 128‐bit temp register
	unsigned char r_array[MAX_CT_SIZE]; // 8‐bit array of 64‐bit registers
	unsigned int i,j; // loop counters
	int outlen;

#if DEBUG
	printf("Key Encryption Key (KEK): ");
	for (i = 0; i < 16; i++)
		printf("%02X", kek[i]);

	printf("\nIV: ");
	for (i = 0; i < 8; i++)
		printf("%02X", iv[i]);

	printf("\nPlaintext: ");
	for (i = 0; i < 40; i++)
		printf("%02X", pt[i]);
#endif

	/*
	 * step 1: initialize the byte‐sized data variables
	 * set A = IV
	 * for i = 1 to n
	 * r_array[i] = P[i]
	 */
	int_chk[0] = iv[0];
	int_chk[1] = iv[1];
	int_chk[2] = iv[2];
	int_chk[3] = iv[3];
	int_chk[4] = iv[4];
	int_chk[5] = iv[5];
	int_chk[6] = iv[6];
	int_chk[7] = iv[7];

	for (i = 1; i <= 5; i++) {
		r_array[8*i+ 0] = pt[8*(i-1)+ 0];
		r_array[8*i+ 1] = pt[8*(i-1)+ 1];
		r_array[8*i+ 2] = pt[8*(i-1)+ 2];
		r_array[8*i+ 3] = pt[8*(i-1)+ 3];
		r_array[8*i+ 4] = pt[8*(i-1)+ 4];
		r_array[8*i+ 5] = pt[8*(i-1)+ 5];
		r_array[8*i+ 6] = pt[8*(i-1)+ 6];
		r_array[8*i+ 7] = pt[8*(i-1)+ 7];
	}

	/*
	 * step 2: calculate intermediate values
	 * for j = 0 to 5
	 * for i = 1 to n
	 * B = AES(K, A | r[i])
	 * A = MSB(64, B) ^ (n*j)+i
	 * r[i] = LSB(64, B)
	 */
	for (j = 0; j <= 5; j++) {
		for (i = 1; i <= 5; i++) {
			temp_in_pt[0] = int_chk[0];
			temp_in_pt[1] = int_chk[1];
			temp_in_pt[2] = int_chk[2];
			temp_in_pt[3] = int_chk[3];
			temp_in_pt[4] = int_chk[4];
			temp_in_pt[5] = int_chk[5];
			temp_in_pt[6] = int_chk[6];
			temp_in_pt[7] = int_chk[7];

			temp_in_pt[8] = r_array[8*i+ 0];
			temp_in_pt[9] = r_array[8*i+ 1];
			temp_in_pt[10] = r_array[8*i+ 2];
			temp_in_pt[11] = r_array[8*i+ 3];
			temp_in_pt[12] = r_array[8*i+ 4];
			temp_in_pt[13] = r_array[8*i+ 5];
			temp_in_pt[14] = r_array[8*i+ 6];
			temp_in_pt[15] = r_array[8*i+ 7];

			// Cipher(in, expanded_kek, 10, b); // perform aes128 encryption

			/* Create and initialise the context */
			if(!(ctx = EVP_CIPHER_CTX_new())) handle_cipher_err();
			/* Set cipher type and mode */
			if(! EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, kek, NULL)) handle_cipher_err();
			/* Setting padding option */
			if(! EVP_CIPHER_CTX_set_padding(ctx, 0)) handle_cipher_err();
			/* Encrypt plaintext */
			if(! EVP_EncryptUpdate(ctx, temp_out_ct, &outlen, temp_in_pt, sizeof(temp_in_pt))) handle_cipher_err();
			/* Finalise the encryption */
			if(! EVP_EncryptFinal_ex(ctx, temp_out_ct + outlen, &outlen)) handle_cipher_err();
			/* Clean up */
			EVP_CIPHER_CTX_free(ctx);

			int_chk[0] = temp_out_ct[0];
			int_chk[1] = temp_out_ct[1];
			int_chk[2] = temp_out_ct[2];
			int_chk[3] = temp_out_ct[3];
			int_chk[4] = temp_out_ct[4];
			int_chk[5] = temp_out_ct[5];
			int_chk[6] = temp_out_ct[6];
			int_chk[7] = temp_out_ct[7] ^ ((5*j)+i);

			r_array[8*i+ 0]= temp_out_ct[8];
			r_array[8*i+ 1]= temp_out_ct[9];
			r_array[8*i+ 2]= temp_out_ct[10];
			r_array[8*i+ 3]= temp_out_ct[11];
			r_array[8*i+ 4]= temp_out_ct[12];
			r_array[8*i+ 5]= temp_out_ct[13];
			r_array[8*i+ 6]= temp_out_ct[14];
			r_array[8*i+ 7]= temp_out_ct[15];

		} // end for (i)
	} // end for (j)

	/*
	 * step 3: output the results
	 * set C[0] = A
	 * for i = 1 to n
	 * C[i] = r[i]
	 */
	ciphertext[0] = int_chk[0];
	ciphertext[1] = int_chk[1];
	ciphertext[2] = int_chk[2];
	ciphertext[3] = int_chk[3];
	ciphertext[4] = int_chk[4];
	ciphertext[5] = int_chk[5];
	ciphertext[6] = int_chk[6];
	ciphertext[7] = int_chk[7];
	for (i = 1; i <= 5; i++) {
		ciphertext[8*i+ 0] = r_array[8*i+ 0];
		ciphertext[8*i+ 1] = r_array[8*i+ 1];
		ciphertext[8*i+ 2] = r_array[8*i+ 2];
		ciphertext[8*i+ 3] = r_array[8*i+ 3];
		ciphertext[8*i+ 4] = r_array[8*i+ 4];
		ciphertext[8*i+ 5] = r_array[8*i+ 5];
		ciphertext[8*i+ 6] = r_array[8*i+ 6];
		ciphertext[8*i+ 7] = r_array[8*i+ 7];
	}

	return &ciphertext[0];
}
