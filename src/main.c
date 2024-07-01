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
#include <time.h>
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


void print_u8(u8 *in, size_t l) {
    for (size_t i = 0; i < l; i++) {
        printf("%02x ", in[i]);
    }
    printf("\n");
}

void print_u32(u32 *in, size_t l) {
    for (size_t i = 0; i < l; i++) {
        printf("%08x ", in[i]);
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    printf("%s\n\n", BANNER);

    int c;
    
    bool encrypt = false;
    bool decrypt = false;

    char *INPUT = (char *)malloc(MAX_PATH);
    char *OUTPUT = (char *)malloc(MAX_PATH);
    char *PASSWORD = (char *)malloc(MAX_PASSWORD);

    if(INPUT == NULL || OUTPUT == NULL || PASSWORD == NULL) {
        fprintf(stderr, "memory allocation failed!\n");
        return 1;
    }

    INPUT[0] = '\0';
    OUTPUT[0] = '\0';
    PASSWORD[0] = '\0';

    while ((c = getopt(argc, argv, "hdei:o:p:")) != -1) { // TODO help 
        switch (c) {
            case 'h':
                printf("Usage: %s [options]\n", argv[0]);
                printf("  -h             show this help message and exit\n");
                printf("  -d             decrypt mode\n");
                printf("  -e             encrypt mode\n");
                printf("  -i <input>     input file\n");
                printf("  -o <output>    output file\n");
                printf("  -p <password>  password\n");
                return 0;
            case 'e':
                if (decrypt) {
                    fprintf(stderr, "cannot set both -e and -d options\n");
                    return 1;
                }
                encrypt = true;
                break;
            case 'd':
                if (encrypt) {
                    fprintf(stderr, "cannot set both -e and -d options\n");
                    return 1;
                }
                decrypt = true;
                break;
            case 'o':
                OUTPUT = optarg;
                break;
            case 'i':
                INPUT = optarg;
                break;
            case 'p':
                PASSWORD = optarg;
                break;
            default:
                fprintf(stderr, "unknown option: %c\n", c);
                return 1;
        }
    }

    if(!(encrypt || decrypt)) {
        fprintf(stderr, "encryption or decryption not specified!\n");
        free(INPUT);
        free(OUTPUT);
        free(PASSWORD);
        return 1;
    }

    if (!INPUT || strlen(INPUT) == 0) {
        fprintf(stderr, "input file not specified!\n");
        free(INPUT);
        free(OUTPUT);
        free(PASSWORD);
        return 1;
    }

    if (!OUTPUT || strlen(OUTPUT) == 0) {
        fprintf(stderr, "output file not specified!\n");
        free(INPUT);
        free(OUTPUT);
        free(PASSWORD);
        return 1;
    }


    if (!PASSWORD || strlen(PASSWORD) == 0) {
        #ifdef _WIN32
            printf("password: ");
            fflush(stdout);

            while (1) {
                int ch = _getch();
                if(ch == 0x03) {
                    free(PASSWORD);
                    free(OUTPUT);
                    free(INPUT);
                    return 0;
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
                    strncat(PASSWORD, (char[2]){ch, '\0'}, 1);
                }
            }
            PASSWORD[strlen(PASSWORD)] = '\0';
            printf("\n");
        #else
            fflush(stdout);
            char *password_ptr = getpass("password: ");
            strcpy(PASSWORD, password_ptr);
            free(password_ptr);
        #endif
    }

    FCRYPT_CTX *ctx = (FCRYPT_CTX *)malloc(sizeof(FCRYPT_CTX));
    u8 *iv = (u8 *)malloc(16);

    init_fcrypt_ctx(ctx, PASSWORD, strlen(PASSWORD), iv);

    FILE *input_file = fopen(INPUT, "rb");
    if(input_file == NULL) {
        fprintf(stderr, "error opening input file!\n");
        free(PASSWORD);
        free(OUTPUT);
        free(INPUT);
        return 1;
    }

    FILE *output_file = fopen(OUTPUT, "wb");
    if(output_file == NULL) {
        fprintf(stderr, "error opening output file!\n");
        free(PASSWORD);
        free(OUTPUT);
        free(INPUT);
        return 1;
    }

    if(encrypt) {
        u8 *plaintext = read_raw(ctx, input_file);
        fclose(input_file);

        write_fcrypt_file(ctx, output_file, plaintext);
        fclose(output_file);

        free(ctx);
        free(iv);
        free(PASSWORD);
        free(INPUT);
        free(OUTPUT);
        return 0;
    } else if (decrypt) {
        u8 *plaintext = read_fcrypt_file(ctx, input_file);
        fclose(input_file);

        fwrite(plaintext, sizeof(u8), ctx->data_size-16, output_file); // i don't really know why but it works correctly only if i subtract 16 from data_size
        fclose(output_file);

        free(ctx);
        free(iv);
        free(PASSWORD);
        free(INPUT);
        free(OUTPUT);
        return 0;
    }
    
}