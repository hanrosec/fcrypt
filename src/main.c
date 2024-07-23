/**
 * Encrypted file structure .fc
 * 
 * sizes:
 *  SHA3(PASSWORD, 256): 32 (u8)
 *  iv: 16 (u8)
 *  sums up to 48 (u8) bytes header
 * 
 * file structure:
 *  SHA3(PASSWORD, 256) || iv || encrypted data
 * 
 * key will be derived from plaintext PASSWORD
 * 
 * encryption:
 *  1. get PASSWORD from user
 *  2. initialize ctx:
 *      1. derive key and add it to ctx
 *      2. generate iv and add it to ctx
 *  3. read data from file
 *  4. encrypt data
 *  5. create file header
 *  6. file creation:
 *      1. write header
 *      2. write encrypted data
 * 
 * decryption:
 *  1. read first 32 (u8) bytes and write it to ctx
 *  2. read next 12 (u8) bytes and write it to ctx
 *  3. read rest of file
 *  4. decrypt file
 *  5. write decrypted data to file
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include <getopt.h>

#ifdef _WIN32
    #include <conio.h>
    #define MAX_PATH 256
#else
    #include <unistd.h>
    #define MAX_PATH 4096
    extern char *getpass(const char *prompt);
#endif

#define MAX_PASSWORD 257 // 256+1 for null terminator

#define FREE_INPUTS \
        free(INPUT); \
        free(OUTPUT); \
        free(PASSWORD);

bool verbose = false;

#include "pbkdf.h"
#include "fcrypt.h"
#include "types.h"

const u8 *BANNER = (const u8 *)
"  __                       _   \n"
" / _| ___ _ __ _   _ _ __ | |_ \n"
"| |_ / __| '__| | | | '_ \\| __|\n"
"|  _| (__| |  | |_| | |_) | |_ \n"
"|_|  \\___|_|   \\__, | .__/ \\__|\n"
"               |___/|_|        ";

int main(int argc, char *argv[]) {
    printf("%s\n\n", BANNER);

    int c;

    bool encrypt = false;
    bool decrypt = false;

    char *INPUT = (char *)calloc(MAX_PATH, sizeof(char));
    char *OUTPUT = (char *)calloc(MAX_PATH, sizeof(char));
    char *PASSWORD = (char *)calloc(MAX_PASSWORD, sizeof(char));

    if(INPUT == NULL || OUTPUT == NULL || PASSWORD == NULL) {
        fprintf(stderr, "memory allocation failed!\n");
        FREE_INPUTS;
        return 1;
    }

    INPUT[0] = '\0';
    OUTPUT[0] = '\0';
    PASSWORD[0] = '\0';

    while ((c = getopt(argc, argv, "hvdei:o:p:")) != -1) {
        switch (c) {
            case 'h':
                printf("Usage: %s [options]\n", argv[0]);
                printf("  -h             show this help message and exit\n");
                printf("  -v             verbose\n");
                printf("  -d             decrypt mode\n");
                printf("  -e             encrypt mode\n");
                printf("  -i <input>     input file\n");
                printf("  -o <output>    output file\n");
                printf("  -p <password>  password\n");
                return 0;
            case 'e':
                if (decrypt) {
                    fprintf(stderr, "cannot set both -e and -d options\n");
                    FREE_INPUTS;
                    return 1;
                }
                encrypt = true;
                break;
            case 'd':
                if (encrypt) {
                    fprintf(stderr, "cannot set both -e and -d options\n");
                    FREE_INPUTS;
                    return 1;
                }
                decrypt = true;
                break;
            case 'o':
                strncpy(OUTPUT, optarg, MAX_PATH - 1);
                break;
            case 'i':
                strncpy(INPUT, optarg, MAX_PATH - 1);
                break;
            case 'p':
                strncpy(PASSWORD, optarg, MAX_PASSWORD - 1);
                break;
            case 'v':
                verbose = true;
                break;
            default:
                fprintf(stderr, "unknown option: %c\n", c);
                FREE_INPUTS;
                return 1;
        }
    }

    if(!(encrypt || decrypt)) {
        fprintf(stderr, "encryption or decryption not specified!\n");
        FREE_INPUTS;
        return 1;
    }

    if (strlen(INPUT) == 0) {
        fprintf(stderr, "input file not specified!\n");
        FREE_INPUTS;
        return 1;
    }

    if (strlen(OUTPUT) == 0) {
        fprintf(stderr, "output file not specified!\n");
        FREE_INPUTS;
        return 1;
    }


    if (strlen(PASSWORD) == 0) {
        const char *prompt = "password (max 256 characters): ";
        #ifdef _WIN32
            printf(prompt);
            fflush(stdout);

            while (1) {
                char ch = _getch();
                if(ch == 0x03) {
                    free(OUTPUT);
                    FREE_INPUTS;
                }
                if (ch == '\r' || ch == '\n') {
                    break;
                }
                if (ch == '\b') {
                    if (strlen(PASSWORD) > 0) {
                        printf("\b \b");
                        PASSWORD[strlen(PASSWORD) - 1] = '\0';
                    }
                } else {
                    printf("*");

                    if (strlen(PASSWORD) + 1 < MAX_PASSWORD) {
                        strncat(PASSWORD, &ch, 1);
                    } else {
                        fprintf(stderr, "\npassword is too long! EXITING!\n");
                        FREE_INPUTS;
                        return 1;
                    }
                }
            }
            PASSWORD[strlen(PASSWORD)] = '\0';
            printf("\n");
        #else
            fflush(stdout);
            char *password_ptr = getpass(prompt);
            strncpy(PASSWORD, password_ptr, MAX_PASSWORD - 1);
        #endif
    }

    FCRYPT_CTX *ctx = (FCRYPT_CTX *)malloc(sizeof(FCRYPT_CTX));
    if (!ctx) {
        fprintf(stderr, "error initializing fcrypt context!\n");
        FREE_INPUTS;
        return 1;
    }

    u8 *iv = (u8 *)calloc(16, 1);
    if (!iv) {
        fprintf(stderr, "error allocating IV!\n");
        free(ctx);
        FREE_INPUTS;
        return 1;
    }

    init_fcrypt_ctx(ctx, PASSWORD, strlen(PASSWORD), iv);
    memset(PASSWORD, 0, MAX_PASSWORD);

    if(verbose) printf("opening input file: %s\n", INPUT);
    FILE *input_file = fopen(INPUT, "rb");
    if(input_file == NULL) {
        fprintf(stderr, "error opening input file!\n");
        free(iv);
        free(ctx);
        FREE_INPUTS;
        return 1;
    }
    if(verbose) printf("successfully opened input file!\n");
    
    if(verbose) printf("opening output file: %s\n", OUTPUT);
    FILE *output_file = fopen(OUTPUT, "wb");
    if(output_file == NULL) {
        fprintf(stderr, "error opening output file!\n");
        fclose(input_file);
        free(iv);
        free(ctx);
        FREE_INPUTS;
    }
    if(verbose) printf("successfully opened output file!\n");

    if(encrypt) {
        u8 *plaintext = read_raw(ctx, input_file);
        fclose(input_file);

        write_fcrypt_file(ctx, output_file, plaintext);
        fclose(output_file);
        free(plaintext);
    } else if (decrypt) {
        u8 *plaintext = read_fcrypt_file(ctx, input_file);
        fclose(input_file);
        if(plaintext == NULL) {
            fprintf(stderr, "wrong password!\n");
            fclose(output_file);
            free(iv);
            free(ctx);
            FREE_INPUTS;
        }

        fwrite(plaintext, sizeof(u8), ctx->data_size - 16, output_file); // i don't really know why but it works correctly only if i subtract 16 from data_size
        fclose(output_file);
        free(plaintext);
    }

    free(ctx);
    free(iv);
    FREE_INPUTS;
}