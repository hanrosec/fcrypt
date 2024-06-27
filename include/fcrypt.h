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

void init_fcrypt_ctx(FCRYPT_CTX *ctx, u8 *password, u8 password_len, u32 *nonce);
void generate_nonce(u32 *nonce);
u8 *encrypt_data(FCRYPT_CTX *ctx, u8 *data);

u8 *read_data(FILE *fptr);
void write_data(FILE *fptr, u8 *data);

void get_password(FCRYPT_CTX *ctx);

#endif /* _FCRYPT_H */