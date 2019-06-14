#include "key_wrap.h"
#include "compute_crc32.h"
#include "aes128_key_wrap.h"

/*
 * Description : This function calls aes128_key_wrap function with input
 *               parameters
 * @input  : plaintext  - Plaintext
 *           iv         - Initialization Vector
 *           kek        - Key Encrpytion Key
 * @output : ciphertext - Ciphertext
 *
 */
unsigned char *do_aes128_key_wrap(unsigned char *in_plaintext, unsigned char *in_kek)
{
        static unsigned char *wrapped_ciphertext;

        wrapped_ciphertext = aes128_key_wrap(in_plaintext, iv, in_kek);

#if DEBUG
        int i;
        printf("\nCiphertext: ");
        for (i = 0; i < MAX_CT_SIZE; i++)
                printf("%02X", wrapped_ciphertext[i]);
#endif

        return &wrapped_ciphertext[0];
}

/*
 * Description : This function reads the input file and returns size
 *
 * @input  : fp         - Input file pointer
 *           input_file - Input file name
 *
 * @output : return File size
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
 * @input  : fp         - Input file pointer
 *           input_file - Input file name
 *
 * @output : return buffer pointer
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
 * @output : The usage info will be printed out on console window.
 */
void print_usage(void) {

        int i = 0;
        printf("OTFAD: Image Encryption Key Wrapper tool\n"
                "Usage:\n"
                "\t./key_wrap (Sample test values used. Output is stdout.)\n"
                "\t./key_wrap ");
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
 * @input     : Command line arguments
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
        do
        {
                next_opt = getopt_long(argc, argv, short_opt, long_opt, NULL);
                switch (next_opt)
                {
                case 'i':
                case 'k':
                case 'c':
                case 's':
                case 'e':
                case 'o':
                        mandatory_opt++;
                        break;
                case '?':
                        /* Input option with no parameter */
                        if ((optopt == 'i' || \
                             optopt == 'k' || \
                             optopt == 'c' || \
                             optopt == 's' || \
                             optopt == 'e' || \
                             optopt == 'o') && (optarg == NULL)) {
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
                        /* 6 mandatory options */
                        if (mandatory_opt != 6 && next_opt == -1) {
                                printf("Error: -i, -k, -c, -s, -e and -o options are required\n");
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

        unsigned char *unwrapped_plaintext = NULL;
        unsigned char *in_otfad_key = NULL;
        unsigned char *aes_key_wrap = NULL;
        uint8_t *in_enc_key = NULL;
        uint8_t *in_counter = NULL;
        uint32_t start_addr = 0;
        uint32_t end_addr = 0;
        uint32_t crc32 = 0;

        uint32_t temp[4] = {0};
        int vld = 0; //Valid bit
        char *output_fname = NULL;
        int i = 0;
        int next_opt = 0;

        if (argc != 1) {
                handle_cli(argc, argv);

                /* Start from the first command-line option */
                optind = 0;
                /* Perform actions according to command-line option */
                do
                {
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
                        /* Image Encryption Key Buffer */
                        case 'k':
                                in_enc_key = alloc_buffer(fp_in, optarg, AES_KEY_SIZE);
                                if (in_enc_key == NULL) {
                                        printf("Error: Error allocating memory for Image Encryption Key\n");
                                        goto err;
                                }
                                break;
                        /* CTR buffer */
                        case 'c':
                                in_counter = alloc_buffer(fp_in, optarg, CTR_SIZE);
                                if (in_counter == NULL) {
                                        printf("Error: Error allocating memory for Counter\n");
                                        goto err;
                                }
                                break;
                        /* Start Address */
                        case 's':
                                /* Least Significant 9 bits are reserved as 0 */
                                start_addr = (strtol(optarg, NULL, 16) & SRT_ADDR_MASK);
                                break;
                        /* End Address */
                        case 'e':
                                end_addr = (strtol(optarg, NULL, 16) & END_ADDR_MASK) | END_ADDR_RSVD | RO | ADE;
                                break;
                        /* Valid bit */
                        case 'v':
                                vld = 1;
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
                        default:
                                break;
                        }
                } while (next_opt != -1);

                /* Append Valid bit to End address */
                end_addr = end_addr | (vld << CTX_RGD_W_VLD_SHIFT);

                /* Prepare plaintext */
                /* key + ctr +
                 * rgd_w0 <-- start_addr +
                 * rgd_w1 <-- end_addr + AES decryption enabled + valid context
                 * crc_w0 <-- CRC Filler
                 * crc_w1 <-- Calculated CRC
                 */
                unwrapped_plaintext = malloc(MAX_PT_SIZE);
                memcpy(unwrapped_plaintext, in_enc_key, AES_KEY_SIZE);
                memcpy(unwrapped_plaintext + AES_KEY_SIZE, in_counter, CTR_SIZE);
                *(uint32_t *)&unwrapped_plaintext[AES_KEY_SIZE + CTR_SIZE] = start_addr;
                *(uint32_t *)&unwrapped_plaintext[AES_KEY_SIZE + CTR_SIZE + 4] = end_addr;
                *(uint32_t *)&unwrapped_plaintext[AES_KEY_SIZE + CTR_SIZE + 8] = CRC32_FILLER;

                crc32 = compute_crc32(unwrapped_plaintext, 32);

                *(uint32_t *)&unwrapped_plaintext[AES_KEY_SIZE + CTR_SIZE + 12] = crc32;
                FREE(in_enc_key);
                FREE(in_counter);

#if DEBUG
                printf("Start Address = 0x%08X\n", start_addr);
                printf("End Address = 0x%08X\n", end_addr);
                printf("CRC32 = 0x%08X\n", crc32);
#endif
        }
        else {
                printf("Running test key wrapping sequence (Enable DEBUG)\n");
                /* Standard output selected*/
                fp_out = stdout;
                in_otfad_key = (unsigned char *)test_otfad_key;
                unwrapped_plaintext = (unsigned char *)test_pt;
        }

        /* Wrap the Image Encryption key */
        aes_key_wrap = do_aes128_key_wrap(unwrapped_plaintext, in_otfad_key);
        if(aes_key_wrap == NULL) {
                printf("Error: Key Wrapping failed\n");
                goto err;
        }

        /*
         *  For MX7D:
         *  1. Post swap needed, given otfad_io will do the bytes swap within every
         *     64bits wrapped data before send them to aes engine.
         *  2. otp_key[127:0] should be byte reversed compared with KEK string.
         *     For example, KEK=00112233445566778899AABBCCDDEEFF, the otp_key should be:
         *     otp_key[127:0] = 128'h33221100_77665544_BBAA9988_FFEEDDCC
         */
        for (i = 0; i < MAX_CT_SIZE; i += 16) {
                memcpy(temp, &aes_key_wrap[i], 16);
                temp[0] = __builtin_bswap32(temp[0]);
                temp[1] = __builtin_bswap32(temp[1]);
                temp[2] = __builtin_bswap32(temp[2]);
                temp[3] = __builtin_bswap32(temp[3]);
                SWAP32(temp[0], temp[1]);
                SWAP32(temp[2], temp[3]);
                memcpy(&aes_key_wrap[i], temp, 16);
        }

        /* stdout selected for test mode */
        if (argc == 1) {
#if DEBUG
                printf("\nOutput Key Blob:");
                for (i = 0; i < MAX_CT_SIZE; i++) {
                        printf("%02X", aes_key_wrap[i]);
                }

                for (i = 0; i < PAD_SIZE; i++) {
                        printf("%s","00");
                }
                printf("\n");
#endif
        }
        /* Key blob output written to the output file */
        else {
                /* Write ciphertext to file */
                if(MAX_CT_SIZE != fwrite((const char *)aes_key_wrap, 1, MAX_CT_SIZE, fp_out)) {
                        printf("Error: File write failed\n");
                        goto err;
                }

                /* Pad file to 0x40 */
                i = PAD_SIZE;
                while(i) {
                        fputc(0, fp_out);
                        i--;
                }


#if DEBUG
                /* Go to the beginning of the output file to print its contents */
                rewind(fp_out);

                printf("\nOutput Key Blob: ");
                int c = 0;
                i = 0;
                do {
                        c = fgetc(fp_out);
                        fprintf(stdout,"%02X", c);
                        i++;
                } while(c != EOF && i < (MAX_CT_SIZE + PAD_SIZE));
                printf("\n");
#endif

                FREE(unwrapped_plaintext);
                FCLOSE(fp_out);
        }

        if (argc != 1) {
                FREE(in_otfad_key);
        }

        if (output_fname != NULL) {
                printf("Wrapped Key generated: %s\n", output_fname);
        }

        return EXIT_SUCCESS;
err:
        FREE(unwrapped_plaintext);
        FREE(in_enc_key);
        FREE(in_counter);
        FREE(in_otfad_key);
        FCLOSE(fp_in);
        FCLOSE(fp_out);

        return EXIT_FAILURE;
}
