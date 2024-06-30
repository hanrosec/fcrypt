/**
 * Encrypted file structure .fc
 * 
 * sizes:
 *  SHA3(password, 256): 32 (u8)
 *  iv: 16 (u8)
 *  sums up to 48 (u8) bytes header
 * 
 * file structure:
 *  SHA3(password, 256) || iv || encrypted data
 * 
 * key will be derived from plaintext password
 * 
 * encryption:
 *  1. get password from user
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
    char *_FILE = {"tests/bins/big_random"};

    FCRYPT_CTX *ctx = (FCRYPT_CTX *)malloc(sizeof(FCRYPT_CTX));
    init_fcrypt_ctx(ctx, password, sizeof(password), iv);

    FILE *plaintext_file = fopen(_FILE, "rb");
    u8 *plaintext = read_raw(ctx, plaintext_file);

    FILE *fcrypt_file = fopen("tests/big_random.fc", "wb");
    write_fcrypt_file(ctx, fcrypt_file, plaintext);
    fclose(fcrypt_file);

    free(ctx);

    FCRYPT_CTX *new_ctx = (FCRYPT_CTX *)malloc(sizeof(FCRYPT_CTX));
    init_fcrypt_ctx(new_ctx, password, sizeof(password), iv);

    FILE *ciphertext_file = fopen("tests/big_random.fc", "rb");
    u8 *plaintext2 = read_fcrypt_file(new_ctx, ciphertext_file);
    fclose(ciphertext_file);

    FILE *plaintext2_file = fopen("tests/bins/big_random_decrypted", "wb");
    fwrite(plaintext2, 1, new_ctx->data_size-16, plaintext2_file);
    fclose(plaintext2_file);
}