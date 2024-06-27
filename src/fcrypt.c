#include "fcrypt.h"

u8 *read_data(FCRYPT_CTX *ctx, FILE *fptr) {
    // get size of file
    fseek(fptr, 0, SEEK_END);
    size_t size = ftell(fptr);
    fseek(fptr, 0, SEEK_SET);

    ctx->data_size = size;

    u8 *buffer = (u8 *)malloc(size * sizeof(u8));
    if(buffer == NULL) {
        fprintf(stderr, "error allocating memory\n");
        return;
    }

    char ch;
    size_t i = 0;
    do {
        ch = getc(fptr);
        buffer[i++] = ch;
    } while(ch != EOF);

    return buffer;
}

void init_fcrypt_ctx(FCRYPT_CTX *ctx, u8 *password, u8 password_len, u32 *nonce) {
    /**
     * 1. derive key from password
     * 2. set key in ctx
     * 3. set nonce in ctx
     */
    u8 key[KEY_SIZE*4];
    u32 lkey[KEY_SIZE];
    u8 processed_password[32];
    
    sha3(password, password_len, ctx->password_hash, 32);

    process_password(password, password_len, processed_password);

    pbkdf(processed_password, 32, 0, key, 32);

    for (size_t i = 0; i < 8; i ++) {
        u8_to_u32(&key[i * 4], &lkey[i]);
    }

    memcpy(ctx->key, lkey, KEY_SIZE);
    memcpy(ctx->nonce, nonce, NONCE_SIZE);
}

void generate_nonce(u32 *nonce) {
    u8 random_bytes[NONCE_SIZE*4];
    for (size_t i=0; i<NONCE_SIZE*4; i++) {
        u8 rand_byte;
        
        #if defined(_WIN32) || defined(_WIN64)
            rand_byte = rand() % 256;
        #else
            FILE *urandom = fopen("/dev/urandom", "r");
            if (urandom == NULL) {
                rand_byte = rand() % 256;
            } else {
                rand_byte = getc(urandom);
            }
            fclose(urandom);
        #endif

        random_bytes[i] = rand_byte;
        // TODO use better PRNG
        // consider using linux (/dev/urandom)
    }

    for (size_t i = 0; i < NONCE_SIZE; i++) {
        u8_to_u32(&random_bytes[i*4], &nonce[i]);
    }
}

void encrypt_data(FCRYPT_CTX *ctx, u8 *plaintext, u8 *ciphertext) {
    encrypt(plaintext, ctx->data_size, ctx->key, ctx->nonce, ciphertext);
}

void decrypt_data(FCRYPT_CTX *ctx, u8 *ciphertext, u8 *plaintext) {
    decrypt(ciphertext, ctx->data_size, ctx->key, ctx->nonce, plaintext);
}
