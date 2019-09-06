#include "key_scrambler.h"

/*
 * Description : This function scrambles the input OTFAD key
 *
 * @Inputs  : otfad_key - OTFAD Key encryption key
 *            key_scramble - Input key scramble
 *            key_scramble_align - Input key scramble align
 *
 * @Outputs : scrambled_kek - Scrambled OTFAD key encryption key
 *
 */
unsigned char *scramble_otfad_key(unsigned char *otfad_key, unsigned char *key_scramble, uint8_t key_scramble_align, int ctx_sel)
{
	unsigned char *scrambled_kek = NULL;
	int i = 0, j = 0, k = 0;

	scrambled_kek = malloc(OTFAD_KEY_SIZE);
	memcpy(scrambled_kek, otfad_key, OTFAD_KEY_SIZE);

	/*
	 * retrieve the 2‐bit align select from the 8‐bit key_scramble_align
	 * context_0_select = key_scramble_align[1:0]
	 * context_1_select = key_scramble_align[3:2]
	 * context_2_select = key_scramble_align[5:4]
	 * context_3_select = key_scramble_align[7:6]
	 */
	j = 2 * ctx_sel;
	k = ((key_scramble_align & (3 << j)) >> j);
	/* XOR 4‐byte key_scramble[] into appropriate 4‐bytes of scrambled_kek[] output */
	for (i = 0; i < 4; i++) {
		scrambled_kek[4*k + i] ^= key_scramble[i];
	}

	return &scrambled_kek[0];
}

/*
 * Description : This function reads the input file and returns size
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
		fprintf(stderr, "Couldn't open file %s; %s\n", input_file, strerror(errno));
		return -1;
	}

	/* Seek to the end of file to calculate size */
	if (fseek(*fp , 0 , SEEK_END)) {
		errno = ENOENT;
		fprintf(stderr, "Couldn't seek to end of file %s; %s\n", input_file, strerror(errno));
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
 * @Inputs  : fp         - Input file pointer
 *            input_file - Input file name
 *
 * @Outputs : return buffer pointer
 *
 */
static unsigned char *alloc_buffer(FILE *fp, char *input_file, int check_size)
{
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
 * Description : Prints the usage information for running key_wrap
 *
 * @Outputs : The usage info will be printed out on console window.
 */
void print_usage(void)
{
	int i = 0;
	printf("OTFAD: Key scrambler tool\n"
		"Usage:\n"
		"\t./key_scramble (Sample test values used. Output is stdout.)\n"
		"\t./key_scramble ");
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
void handle_cli(int argc, char **argv)
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
	do {
		next_opt = getopt_long(argc, argv, short_opt, long_opt, NULL);
		switch (next_opt)
		{
		case 'i':
		case 'k':
		case 'a':
		case 'o':
		case 'c':
			mandatory_opt++;
			break;
		case '?':
			/* Input option with no parameter */
			if ((optopt == 'i' || \
			     optopt == 'k' || \
			     optopt == 'a' || \
			     optopt == 'o' || \
			     optopt == 'c') && (optarg == NULL)) {
				print_usage();
				exit(EXIT_FAILURE);
			}
			/* Unknown character returned */
			print_usage();
			exit(EXIT_FAILURE);
			break;
		/* Display usage */
		case 'h':
			print_usage();
			exit(EXIT_SUCCESS);
			break;
		default:
			/* 5 mandatory options */
			if (mandatory_opt != 5  && next_opt == -1) {
				printf("Error: All options are required\n");
				print_usage();
				exit(EXIT_FAILURE);
			}
			break;
		}
	} while (next_opt != -1);

	/* All options required */
	if (argc > n_long_opt) {
		printf("\nError: Incorrect number of options\n");
		print_usage();
		exit(EXIT_FAILURE);
	}
}

int main (int argc, char **argv)
{
	FILE *fp_in = NULL;
	FILE *fp_out = NULL;

	unsigned char *in_otfad_key = NULL;
	unsigned char *in_key_scramble = NULL;
	uint8_t in_key_scramble_align = 0;
	int context = 0;
	unsigned char *otfad_scrambled_key = NULL;
	char *output_fname = NULL;

	int i = 0;
	int next_opt = 0;

	if (argc != 1) {
		handle_cli(argc, argv);

		/* Start from the first command-line option */
		optind = 0;
		/* Perform actions according to command-line option */
		do {
			next_opt = getopt_long(argc, argv, short_opt, long_opt, NULL);
			switch (next_opt)
			{
			/* OTFAD Key Encryption Key */
			case 'i':
				in_otfad_key = alloc_buffer(fp_in, optarg, OTFAD_KEY_SIZE);
				if (in_otfad_key == NULL) {
					printf("Error: Error allocating memory for OTFAD key\n");
					goto err;
				}
				break;
			/* Key Scramble */
			case 'k':
				in_key_scramble = alloc_buffer(fp_in, optarg, KEY_SCRAMBLE_SIZE);
				if (in_key_scramble == NULL) {
					printf("Error: Error allocating memory for Key scramble\n");
					goto err;
				}
				break;
			/* Key Scramble Align */
			case 'a':
				in_key_scramble_align = (strtol(optarg, NULL, BASE_HEX) & KEY_SCRAMBLE_ALIGN_MASK);
				break;
			/* Output file */
			case 'o':
				output_fname = optarg;
				/* Open output file */
				fp_out = fopen(optarg, "w+b");
				if (fp_out == NULL) {
					fprintf(stderr, "Couldn't open file %s; %s\n", optarg, strerror(errno));
					goto err;
				}
				break;
			/* Context */
			case 'c':
				context = strtol(optarg, NULL, BASE_HEX) & 3;
			default:
				break;
			}
		} while (next_opt != -1);
	}
	else {
		printf("Running test key scrambling sequence (Enable DEBUG)\n");
		/* Standard output selected*/
		fp_out = stdout;
		in_otfad_key = (unsigned char *)test_otfad_key;
		in_key_scramble = (unsigned char *)test_key_scramble;
		in_key_scramble_align = test_key_scramble_align;
	}

#if DEBUG
	printf("OTFAD key (KEK): ");
	for (i = 0; i < OTFAD_KEY_SIZE; i++) {
		printf("%02X", in_otfad_key[i]);
	}

	printf("\nKey Scramble: ");
	for (i = 0; i < KEY_SCRAMBLE_SIZE; i++) {
		printf("%02X", in_key_scramble[i]);
	}

	printf("\nKey Scramble Align: %02X", in_key_scramble_align);
#endif

	/*
	 * According to OTFAD engine's integration with 7ULP
	 * the Scramble Key needs to be bit reversed at byte level.
	 */
	for (i = 0; i < KEY_SCRAMBLE_SIZE; i++) {
		BIT_REVERSE8(in_key_scramble[i]);
	}

#if DEBUG
	printf("\nKey Scramble (After bit reversal): ");
	for (i = 0; i < KEY_SCRAMBLE_SIZE; i++) {
		printf("%02X", in_key_scramble[i]);
	}
#endif
	otfad_scrambled_key = scramble_otfad_key(in_otfad_key, in_key_scramble, in_key_scramble_align, context);
	if(otfad_scrambled_key == NULL) {
		printf("Error: Key Scrambling failed\n");
		goto err;
	}

	if (argc == 1) {
#if DEBUG
		printf("\nOTFAD Scrambled Key: ");
		for (i = 0; i < OTFAD_KEY_SIZE; i++) {
			printf("%02X", otfad_scrambled_key[i]);
		}
		printf("\n");
#endif
	}
	/* OTFAD scrambled key output written to the output file */
	else {
	/* Write ciphertext to file */
		if(OTFAD_KEY_SIZE != fwrite((const char *)otfad_scrambled_key, 1, OTFAD_KEY_SIZE, fp_out)) {
			printf("Error: File write failed\n");
			goto err;
		}

#if DEBUG
		/* Go to the beginning of the output file to print its contents */
		rewind(fp_out);

		printf("\nOTFAD Scrambled Key: ");
		for (i = 0; i < OTFAD_KEY_SIZE; i++) {
			printf("%02X", otfad_scrambled_key[i]);
		}
		printf("\n");
#endif
		FREE(in_otfad_key);
		FREE(in_key_scramble);
		FCLOSE(fp_out);
	}

	if (output_fname != NULL) {
		printf("OTFAD Scrambled Key generated: %s\n", output_fname);
	}

	FREE(otfad_scrambled_key);
	return EXIT_SUCCESS;
err:
	FREE(in_otfad_key);
	FREE(in_key_scramble);
	FREE(otfad_scrambled_key);
	FCLOSE(fp_out);
	return EXIT_FAILURE;
}
