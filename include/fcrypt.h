#ifndef _FCRYPT_H
#define _FCRYPT_H

#include <stdint.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <stdbool.h>

#include "types.h"
#include "pbkdf.h"

extern bool verbose;

typedef struct fcrypt_ctx {
    u8 password_hash[32];
    u8 iv[16];
    u8 key[32];
    int data_size;
} FCRYPT_CTX;

void init_fcrypt_ctx(FCRYPT_CTX *ctx, char *password, u8 password_len, u8 *iv);

int encrypt_data(FCRYPT_CTX *ctx, u8 *plaintext, int plaintext_len, u8 *ciphertext);
int decrypt_data(FCRYPT_CTX *ctx, u8 *ciphertext, int ciphertext_len, u8 *plaintext);

u8 *read_raw(FCRYPT_CTX *ctx, FILE *fptr);
u8 *read_fcrypt_file(FCRYPT_CTX *ctx, FILE *fptr);
void write_fcrypt_file(FCRYPT_CTX *ctx, FILE *fptr, u8 *data);

void sha3_256(const unsigned char *data, size_t data_len, unsigned char *hash);

#endif /* _FCRYPT_H */