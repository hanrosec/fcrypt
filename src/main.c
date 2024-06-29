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

#include "chacha.h"
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
        if((i+1) % 64 == 0) {
            printf("\n");
        }
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

    u8 password[32] = {"5af0d8572a400b395af0d8572a400b39"};
    FCRYPT_CTX *ctx = (FCRYPT_CTX *)malloc(sizeof(FCRYPT_CTX));

    u32 nonce[NONCE_SIZE] = {0x87664050, 0x2d587718, 0x90fecbf1};
    // generate_nonce(nonce);

    // printf("nonce: ");
    // print_u32(nonce, NONCE_SIZE);

    init_fcrypt_ctx(ctx, password, sizeof(password), nonce);

    // printf("password: ");
    // print_u8(password, sizeof(password));

    printf("SHA3(password, 256): ");
    print_u8(ctx->password_hash, 32);

    FILE *fp = fopen("tests/big_file", "r");
    if(fp == NULL) {
        fprintf(stderr, "error opening file\n");
        return -1;
    }

    u8 *data = read_raw(ctx, fp);

    fclose(fp);

    write_fcrypt_file(ctx, fopen("tests/output", "w"), data);

    u8 *plaintext = read_fcrypt_file(ctx, fopen("tests/output", "r"));
    
    print_u8(plaintext, 65*7);
}