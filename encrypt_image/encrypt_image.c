#include "encrypt_image.h"

/*
 * Description : Handles error generated from EVP CIPHER operations.
 *               Aborts execution upon error detection.
 */
void handle_cipher_err(void)
{
	ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
}

/*
 * Description : Performs AES CTR operation on plaintext to produce ciphertext
 *
 * @Inputs  : plaintext - Plaintext to encrypt
 *            size      - Plaintext size
 *            key       - Key used to encrypt plaintext
 *            ctr       - Counter used to encrypt plaintext
 *            sys_addr  - System Address used to change counter per encryption block
 *
 * @Outputs : return Ciphertext
 *
 */
unsigned char *do_aes_ctr_enc(uint8_t *plaintext, int size, unsigned char *key, unsigned char *ctr, uint32_t sys_addr)
{
	EVP_CIPHER_CTX *ctx;
	int outlen;
	static unsigned char cipher[MAX_SIZE];
	static unsigned char enc_ctr[16];
	static unsigned char swap_enc_ctr[16];
	uint32_t temp[4];
	int encrypted_bytes = 0;
	int i = 0;
	int j = 0;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) handle_cipher_err();

	/* Set cipher type and mode */
	if(! EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL)) handle_cipher_err();

#if DEBUG
	int iter;
	/* Number of iterations = total size to encrypt/16 bytes of each encryption block */
	iter = size/16;
	printf("Total Iterations : %d\n", iter);
#endif
	for (i = 0; i < size; i += 16) {
		/* Calculate CTR value in each iteration */
		sys_addr += encrypted_bytes;
#if DEBUG
		printf("\nIteration : %d\n", i/16);
		printf("System address in Iteration %d = 0x%08X\n", i/16, sys_addr);
#endif
		ctr[SYS_ADDR_OFFSET] = (uint8_t)((sys_addr >> 24) & 0xFF);
		ctr[SYS_ADDR_OFFSET + 1] = (uint8_t)((sys_addr >> 16) & 0xFF);
		ctr[SYS_ADDR_OFFSET + 2] = (uint8_t)((sys_addr >> 8) & 0xFF);
		ctr[SYS_ADDR_OFFSET + 3] = (uint8_t)(sys_addr & 0xFF);

#if DEBUG
		printf("\nInput Counter:\t\t\t");
		for (j = 0; j < 16; ++j) {
			 printf("%02X", ctr[j]);
		}
#endif
		/*setting padding option*/
		if(! EVP_CIPHER_CTX_set_padding(ctx, 0)) handle_cipher_err();
		/* Encrypt plaintext */
		if(! EVP_EncryptUpdate(ctx, enc_ctr, &outlen, ctr, 16)) handle_cipher_err();

		/* Increment encrypted bytes */
		encrypted_bytes = outlen;

#if DEBUG
		printf("\nEncrypted Counter:\t\t");
		for (j = 0; j < 16; ++j) {
			printf("%02X", enc_ctr[j]);
		}
#endif
		/* Finalise the encryption */
		if(! EVP_EncryptFinal_ex(ctx, enc_ctr + outlen, &outlen)) handle_cipher_err();

		/* Swap Encrypted Counter as per OTFAD */
		memcpy(temp, enc_ctr, 16);
		temp[0] = __builtin_bswap32(temp[0]);
		temp[1] = __builtin_bswap32(temp[1]);
		temp[2] = __builtin_bswap32(temp[2]);
		temp[3] = __builtin_bswap32(temp[3]);
		SWAP32(temp[0], temp[1]);
		SWAP32(temp[2], temp[3]);
		memcpy(swap_enc_ctr, temp, 16);

		/* XOR Plaintext with Swapped Encripted Counter */
		for (j = 0; j < 16; ++j) {
			cipher[i + j] = plaintext[i + j] ^ swap_enc_ctr[j];
		}

#if DEBUG       
		printf("\nSwapped Encrypted Counter:\t");
		for (j = 0; j < 16; ++j) {
			 printf("%02X", swap_enc_ctr[j]);
		}

		printf("\nPlaintext Data:\t\t\t");
		for (j = 0; j < 16; ++j) {
			 printf("%02X", plaintext[i + j]);
		}

		printf("\nCipher Output:\t\t\t");
		for (j = 0; j < 16; ++j) {
			 printf("%02X", cipher[i + j]);
		}
		printf("\n");
#endif
	}

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return &cipher[0];
}

/*
 * Description : This function reads the inputs file and returns size
 *
 * @Inputs  : fp         - Input file pointer
 *            input_file - Input file name
 *
 * @Outputs : return File size
 *
 */
static int get_file_size(FILE **fp, char *input_file)
{
	int ret = 0;

	/* Open file */
	*fp = fopen(input_file, "r");
	if (*fp == NULL) {
		fprintf(stderr, "Error: Couldn't open file %s; %s\n", input_file, strerror(errno));
		return -1;
	}

	/* Seek to the end of file to calculate size */
	if (fseek(*fp , 0 , SEEK_END)) {
		errno = ENOENT;
		fprintf(stderr, "Error: Couldn't seek to end of file %s; %s\n", input_file, strerror(errno));
		return -1;
	}

	/* Get size and go back to start of the file */
	ret = ftell(*fp);
	rewind(*fp);

	return ret;
}

/*
 * Description : This function allocates buffer with size from input file
 *
 * @input  : fp         - Input file pointer
 *           input_file - Input file name
 *
 * @output : return buffer pointer
 *
 */
static unsigned char *alloc_buffer(FILE *fp, char *input_file, int check_size)
{
	// int ret = 0;
	int file_size = 0;
	unsigned char *buff = NULL;
	size_t result = 0;

	file_size = get_file_size(&fp, input_file);
	if (file_size < 0 ) {
		fprintf(stderr, "File read error; %s\n", strerror(errno));
		return NULL;
	} else if (file_size != check_size) {
		printf("Error: Incorrect Size\n");
		return NULL;
	}

	/* Allocate memory to the buffer */
	buff = malloc(file_size);
	if (buff == NULL || buff == 0) {
		fprintf(stderr, "Error allocating memory; %s\n", strerror(errno));
		return NULL;
	}

	/* Copy the file into the buffer */
	result = fread(buff,1,file_size,fp);
	if (result != file_size) {
		fprintf(stderr, "File read error; %s\n", strerror(errno));
		return NULL;
	}
	FCLOSE(fp);

	return buff;
}

/*
 * Description : Prints the usage information for running encrypt_image
 *
 * @Outputs : The usage info will be printed out on console window.
 */
void print_usage(void) {
	int i = 0;
	printf("OTFAD: Image Encryption tool\n"
		"Usage: ./encrypt_image ");
	do {
		printf("-%c <%s> ", long_opt[i].val, long_opt[i].name);
		i++;
	} while (long_opt[i + 1].name != NULL);
	printf("\n");

	i = 0;
	printf("Options:\n");
	do {
		printf("\t-%c|--%s  -->  %s\n", long_opt[i].val, long_opt[i].name, opt_desc[i]);
		i++;
	} while (long_opt[i].name != NULL && opt_desc[i] != NULL);
}

/*
 * Description : Handle each command line option
 *
 * @Inputs     : Command line arguments
 */
void handle_cl_opt(int argc, char **argv)
{
	int next_opt = 0;
	int n_long_opt = 1; // Includes the command itself
	int mandatory_opt = 0;
	int i = 0;

	do {
		n_long_opt++;
		if (long_opt[i].has_arg == required_argument) {
			n_long_opt++;
		}
		i++;
	} while (long_opt[i + 1].name != NULL);

	/* Start from the first command-line option */
	optind = 0;
	/* Handle command line options*/
	do
	{
		next_opt = getopt_long(argc, argv, short_opt, long_opt, NULL);
		switch (next_opt)
		{
		case 'i':
		case 'o':
		case 's':
		case 'e':
			mandatory_opt += 1;
			break;
		/* Display usage */
		case 'h':
			print_usage();
			exit(EXIT_SUCCESS);
			break;
		case '?':
			/* Input option with no parameter */
			if ((optopt == 'i' || \
			     optopt == 'o' || \
			     optopt == 's' || \
			     optopt == 'e') && (optarg == NULL)) {
				print_usage();
				exit(EXIT_FAILURE);
			}
			/* Unknown character returned */
			print_usage();
			exit(EXIT_FAILURE);
			break;
		/* At the end reach here and check if mandatory options are present */
		default:
			if (mandatory_opt != 4 && next_opt == -1) {
				printf("Error: -i, -o, -s and -e options are required\n");
				print_usage();
				exit(EXIT_FAILURE);
			}
			break;
		}
	} while (next_opt != -1);

	/* Check for valid arguments */
	if (argc < 2 || argc > n_long_opt) {
		printf("Error: Incorrect number of options\n");
		print_usage();
		exit(EXIT_FAILURE);
	}

}

int main (int argc, char **argv)
{
	FILE *fp_in = NULL;
	FILE *fp_out = NULL;
	FILE *fp_hdr = NULL;

	uint8_t *image_buf = NULL;
	uint8_t *image_hdr_buf = NULL;
	uint8_t *key_buf = NULL;
	uint8_t *ctr_buf = NULL;
	size_t result;
	const unsigned char *enc_image = NULL;

	int image_size = 0;
	int enc_image_size = 0;
	unsigned char *image_enc_key = NULL;
	unsigned char *counter = NULL;
	uint8_t ctr_xor[4];
	uint32_t system_address = 0;
	uint32_t start_address = 0;
	uint32_t end_address = 0;
	uint32_t image_start_offset = 0;

	int next_opt = 0;
	char *output_fname = NULL;
	int i;

	/* Handle command line options */
	handle_cl_opt(argc, argv);

	/* Start from the first command-line option */
	optind = 0;
	/* Perform actions according to command-line option */
	do
	{
		next_opt = getopt_long(argc, argv, short_opt, long_opt, NULL);
		switch (next_opt)
		{
		/* Image Encryption Key */
		case 'k':
			key_buf = alloc_buffer(fp_in, optarg, AES_KEY_SIZE);
			if (key_buf == NULL) {
				printf("Error: Error allocating memory for Image Encryption key\n");
				goto err;
			}
			break;
		/* Counter */
		case 'c':
			ctr_buf = alloc_buffer(fp_in, optarg, CTR_SIZE);
			if (ctr_buf == NULL) {
				printf("Error: Error allocating memory for Counter\n");
				goto err;
			}
			break;
		/* Start Address */
		case 's':
			start_address = strtol(optarg, NULL, BASE_HEX);
			system_address = start_address;
#if DEBUG
			printf("Start Address = 0x%08X\n", start_address);
#endif
			break;
		/* End Address */
		case 'e':
			end_address = strtol(optarg, NULL, BASE_HEX);
#if DEBUG
			printf("End Address = 0x%08X\n", end_address);
#endif
			break;
		/* Ouput file */
		case 'o':
			output_fname = optarg;
			fp_out = fopen(optarg, "wb");
			if (fp_out == NULL) {
				fprintf(stderr, "Error: Couldn't open file %s; %s\n", optarg, strerror(errno));
				goto err;
			}
			break;
		default:
			break;
		}
	} while (next_opt != -1);

	/* Validate start and end address based on QSPI base address */
	if (start_address < MX7ULP_QSPI_BASE_ADDR || \
	    end_address < MX7ULP_QSPI_BASE_ADDR || \
	    end_address <= start_address) {
		printf("Error: End Address should be greater than Start address and greater than QSPI Base Address\n");
		goto err;
	}

	/* Split up the Header and Image according to Start and End Address */
	/* Start from the first command-line option */
	optind = 0;
	/* Perform actions according to command-line option */
	do
	{
		next_opt = getopt_long(argc, argv, short_opt, long_opt, NULL);
		switch (next_opt)
		{
		case 'i':
			image_size = get_file_size(&fp_in, optarg);
			if (image_size < 0) {
				fprintf(stderr, "Error: File read error; %s\n", strerror(errno));
				goto err;
			} else if (image_size <= IMG_HDR_SIZE) {
				printf("Error: File size should be greater than 4096 bytes");
				goto err;
			}

			/* Allocate memory to the buffer - Image header */
			image_hdr_buf = malloc(IMG_HDR_SIZE);
			if (image_hdr_buf == NULL || image_hdr_buf == 0) {
				fprintf(stderr, "Error: Error allocating memory; %s\n", strerror(errno));
				goto err;
			}

			/* Copy the file into the buffer - Image header */
			result = fread(image_hdr_buf,1,IMG_HDR_SIZE,fp_in);
			if (result != IMG_HDR_SIZE) {
				fprintf(stderr, "Error: File read error; %s\n", strerror(errno));
				goto err;
			}

			image_start_offset = start_address - MX7ULP_QSPI_BASE_ADDR;
			/* Seek to the image start offset */
			if (fseek(fp_in , image_start_offset , SEEK_SET)) {
				errno = ENOENT;
				fprintf(stderr, "Error: Couldn't seek to offset 0x1000 %s; %s\n", optarg, strerror(errno));
				goto err;
			}

			enc_image_size = end_address - start_address;

			/* Allocate memory to the buffer - Image to be encrypted */
			image_buf = malloc(enc_image_size);
			if (image_buf == NULL || image_buf == 0) {
				fprintf(stderr, "Error: Error allocating memory; %s\n", strerror(errno));
				goto err;
			}

			/* Copy the file into the buffer - Image to be encrypted */
			result = fread(image_buf,1,enc_image_size,fp_in);
			if (result != enc_image_size) {
				fprintf(stderr, "Error: File read error; %s\n", strerror(errno));
				goto err;
			}

			FCLOSE(fp_in);
			break;
		default:
			break;
		}
	} while (next_opt != -1);

	/* Choose whether to use test key or input key */
	if(key_buf == NULL) {
		image_enc_key = (unsigned char *)test_key;
		printf("Using Test Image Encryption Key as input\n");
#if DEBUG
		printf("Test Input Image Encryption Key:");
#endif
	} else {
		/* Copy key value from input key file */
		image_enc_key = key_buf;
#if DEBUG
		printf("Input Image Encryption Key:");
#endif
	}

#if DEBUG
	for (i = 0; i < AES_KEY_SIZE; i++) {
		printf("%02X", image_enc_key[i]);
	}
	printf("\n");
#endif

	/* Choose whether to use test counter or input counter value*/
	if(ctr_buf == NULL) {
		counter = (unsigned char *)test_ctr;
		printf("Using Test Couter as input\n");
#if DEBUG
		printf("Test Input Counter:");
		for (i = 0; i < CTR_EXT_SIZE; i++) {
			printf("%02X", test_ctr[i]);
		}
		printf("\n");
#endif
	}
	else {
		/* Allocate memory for counter value */
		counter = malloc(CTR_EXT_SIZE);
		if (counter == NULL || counter == 0) {
			fprintf(stderr, "Error: Error allocating memory; %s\n", strerror(errno));
			goto err;
		}

		/* Copy Counter value from input counter file */
		counter = ctr_buf;

		/* Append counter with XOR of 0th byte with 4th byte etc...*/
		for(i = 0; i < 4; i++) {
			ctr_xor[i] = ctr_buf[i] ^ ctr_buf[i + 4];
		}

#if DEBUG
		printf("Input Counter value:");
		for (i = 0; i < CTR_SIZE; i++) {
			printf("%02X", counter[i]);
		}
		printf("\n");

		printf("Counter XOR value\n");
		for(i = 0; i < 4; i++) {
			printf("ctr_xor[%d] = %X\n", i, ctr_xor[i]);
		}

		printf("QSPI System Address = 0x%08X\n", system_address);
#endif
		/* Append Counter XOR value */
		memcpy(counter + CTR_SIZE, ctr_xor, 4);
		/* Append Counter value with QSPI addr */
		memcpy(counter + CTR_SIZE + 4, &system_address, 4);
	}

	/* Perform AES-128-CTR encryption */
	enc_image = do_aes_ctr_enc(image_buf, enc_image_size, image_enc_key, counter, system_address);
	if(enc_image == NULL) {
		printf("Error: Encryption failed\n");
		goto err;
	}

	/* Write the image header to the header file */
	fp_hdr = fopen("header", "wb");
	if (fp_hdr == NULL) {
		fprintf(stderr, "Error: Couldn't open file %s; %s\n", "header", strerror(errno));
		goto err;
	}

	if(IMG_HDR_SIZE != fwrite((const char *)image_hdr_buf, 1, IMG_HDR_SIZE, fp_hdr)) {
		printf("Error: Image header - File write failed\n");
		goto err;
	}

	/* Write Encrypted image to the output file */
	if(enc_image_size != fwrite((const char *)enc_image, 1, enc_image_size, fp_out)) {
		printf("Error: Encrypted Image - File write failed\n");
		goto err;
	}

	printf("Header file generated: header\n");
	printf("Encrypted Image generated: %s\n", output_fname);

	FREE(image_hdr_buf);
	FREE(image_buf);
	FREE(key_buf);
	FREE(ctr_buf);
	FCLOSE(fp_in);
	FCLOSE(fp_out);
	FCLOSE(fp_hdr);

	return EXIT_SUCCESS;
err:
	FREE(image_hdr_buf);
	FREE(image_buf);
	FREE(key_buf);
	FREE(ctr_buf);
	FCLOSE(fp_in);
	FCLOSE(fp_out);
	FCLOSE(fp_hdr);

	return EXIT_FAILURE;
}
