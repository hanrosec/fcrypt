/**
 * Encrypted file structure .fc
 * 
 * sizes:
 *  hashed password: 8 bytes
 *  nonce: 3 bytes
 * 
 * file structure:
 *  hashed_password || nonce || encrypted data
 * 
 * key will be derived from plaintext password
 * 
 * encryption:
 * TODO
 * 
 * decryption:
 * TODO
 */

#include <stdio.h>
#include <time.h>

#include "chacha.h"
#include "pbkdf.h"
#include "fcrypt.h"

const uint8_t *BANNER = (const uint8_t *)
"  __                       _   \n"
" / _| ___ _ __ _   _ _ __ | |_ \n"
"| |_ / __| '__| | | | '_ \\| __|\n"
"|  _| (__| |  | |_| | |_) | |_ \n"
"|_|  \\___|_|   \\__, | .__/ \\__|\n"
"               |___/|_|        ";


void print_u8(uint8_t *in, size_t l) {
    for (size_t i = 0; i < l; i++) {
        printf("%02x ", in[i]);
    }
}

void print_u32(uint32_t *in, size_t l) {
    for (size_t i = 0; i < l; i++) {
        printf("%08x ", in[i]);
    }
}

int main() {
    srand(time(NULL));

    printf("%s\n\n", BANNER);
    uint8_t password[32] = {"5af0d8572a400b395af0d8572a400b39"};
    FCRYPT_CTX *ctx = (FCRYPT_CTX *)malloc(sizeof(FCRYPT_CTX));

    uint32_t nonce[NONCE_SIZE];
    generate_nonce(nonce);

    print_u32(nonce, NONCE_SIZE);

    init_fcrypt_ctx(ctx, password, sizeof(password), nonce);

    FILE *fp = fopen("tests/test_file", "r");

    read_data(ctx, fp);

    fclose(fp);

    printf("\n");
    print_u8(ctx->data, ctx->data_size);
}
