#ifndef _FCRYPT_H
#define _FCRYPT_H

#include <stdint.h>
#include <stdio.h>

#include "types.h"
#include "chacha.h"
#include "pbkdf.h"


typedef struct fcrypt_ctx {
    u8 password_hash[32];
    u32 nonce[NONCE_SIZE];
    u32 key[KEY_SIZE];
} FCRYPT_CTX;

u8 *read_data(FILE *fptr);
void write_encrypted_data(FCRYPT_CTX *ctx, FILE *fptr);
void init_fcrypt_ctx(FCRYPT_CTX *ctx, uint8_t *password, uint8_t password_len, u32 *nonce);
void generate_nonce(u32 *nonce);

#endif /* _FCRYPT_H */