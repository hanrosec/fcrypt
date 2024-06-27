#ifndef _FCRYPT_H
#define _FCRYPT_H

#include <stdint.h>
#include <stdio.h>

#include "chacha.h"
#include "pbkdf.h"


typedef struct fcrypt_ctx {
    uint32_t key[KEY_SIZE];
    uint32_t nonce[NONCE_SIZE];
    uint8_t data_size;
    uint8_t *data;
} FCRYPT_CTX;

void read_data(FCRYPT_CTX *ctx, FILE *fptr);
void write_encrypted_data(FCRYPT_CTX *ctx, FILE *fptr);
void init_fcrypt_ctx(FCRYPT_CTX *ctx, uint8_t *password, uint8_t password_len, uint32_t *nonce);
void generate_nonce(uint32_t *nonce);

#endif /* _FCRYPT_H */