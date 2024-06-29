/**
 * Encrypted file structure .fc
 * 
 * sizes:
 *  SHA3(password, 256): 8 (u32) = 32 (u8)
 *  nonce: 3 (u32) = 12 (u8)
 *  sums up to 44 (u8) bytes header
 * 
 * file structure:
 *  SHA3(password, 256) || nonce || encrypted data
 * 
 * key will be derived from plaintext password
 * 
 * encryption:
 *  1. get password from user
 *  2. initialize ctx:
 *      1. derive key and add it to ctx
 *      2. generate nonce and add it to ctx
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

int main() {
    srand(time(NULL));

    printf("%s\n\n", BANNER);

    char password[4] = {"test"};
    u8 iv[16] = {0xff,0xae,0xdc,0x8c,0xad,0xf2,0x79,0x1c,0x02,0x1c,0xd8,0x17,0x19,0x06,0xa6,0xa2};

    printf("Initializing FCRYPT_CTX...\n");
    FCRYPT_CTX *ctx = (FCRYPT_CTX *)malloc(sizeof(FCRYPT_CTX));
    if (!ctx) {
        fprintf(stderr, "Memory allocation failed.\n");
        return 1;
    }

    printf("Initializing FCRYPT_CTX with password and IV...\n");
    init_fcrypt_ctx(ctx, password, sizeof(password), iv);
    print_u8(ctx->key, sizeof(ctx->key));
    print_u8(ctx->iv, sizeof(ctx->iv));

    printf("Opening input file...\n");
    FILE *fptr = fopen("tests/big_file", "rb");
    if (!fptr) {
        fprintf(stderr, "Failed to open input file.\n");
        free(ctx);
        return 1;
    }

    printf("Reading input file...\n");
    u8 *plaintext = read_raw(ctx, fptr);
    fclose(fptr);
    if (!plaintext) {
        fprintf(stderr, "Failed to read input file.\n");
        free(ctx);
        return 1;
    }

    printf("Encrypting data...\n");
    u8 ciphertext[ctx->data_size];

    print_u8(plaintext, 1024);
    printf("%d\n", ctx->data_size);

    int ciphertext_len = encrypt_data(ctx, plaintext, ctx->data_size, ciphertext);
    if (ciphertext_len < 0) {
        fprintf(stderr, "Failed to encrypt data.\n");
        free(ctx);
        free(plaintext);
        return 1;
    }

    printf("Opening cipher file...\n");
    FILE *fptr2 = fopen("tests/cipher", "wb");
    if (!fptr2) {
        fprintf(stderr, "Failed to open cipher file.\n");
        free(ctx);
        free(plaintext);
        return 1;
    }

    printf("Writing encrypted data to cipher file...\n");
    fwrite(ciphertext, 1, ciphertext_len, fptr2);
    fclose(fptr2);

    free(ctx);
    free(plaintext);

    printf("Initializing new FCRYPT_CTX...\n");
    FCRYPT_CTX *new_ctx = (FCRYPT_CTX *)malloc(sizeof(FCRYPT_CTX));
    init_fcrypt_ctx(new_ctx, password, sizeof(password), iv);

    FILE *fptr3 = fopen("tests/cipher", "rb");
    if (!fptr3) {
        fprintf(stderr, "Failed to open input file.\n");
        free(new_ctx);
        return 1;
    }

    u8 *ciphertext2 = read_raw(new_ctx, fptr3);
    fclose(fptr3);

    if (!ciphertext2) {
        fprintf(stderr, "Failed to read ciphertext.\n");
        free(new_ctx);
        return 1;
    }

    printf("Decrypting data...\n");
    u8 *plaintext2 = (u8 *)malloc(new_ctx->data_size);
    if (!plaintext2) {
        fprintf(stderr, "Failed to allocate memory for decrypted data.\n");
        free(new_ctx);
        free(ciphertext2);
        return 1;
    }

    int plaintext_len = decrypt_data(new_ctx, ciphertext2, new_ctx->data_size, plaintext2);
    if (plaintext_len < 0) {
        fprintf(stderr, "Failed to decrypt data.\n");
        free(new_ctx);
        free(ciphertext2);
        free(plaintext2);
        return 1;
    }

    printf("Opening cipher file for decrypted data...\n");
    FILE *fptr4 = fopen("tests/big_file_decrypted", "wb");
    if (!fptr4) {
        fprintf(stderr, "Failed to open cipher file.\n");
        free(new_ctx);
        free(ciphertext2);
        free(plaintext2);
        return 1;
    }

    printf("Writing decrypted data to cipher file...\n");
    fwrite(plaintext2, 1, plaintext_len, fptr4);
    fclose(fptr4);

    free(new_ctx);
    free(ciphertext2);
    free(plaintext2);

    printf("Decryption successful.\n");
    return 0;
}