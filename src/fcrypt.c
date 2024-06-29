#include "fcrypt.h"

u8 *read_raw(FCRYPT_CTX *ctx, FILE *fptr) {
    // get size of file
    fseek(fptr, 0, SEEK_END);
    ctx->data_size = ftell(fptr);
    fseek(fptr, 0, SEEK_SET);

    u8 *buffer = (u8 *)malloc(ctx->data_size * sizeof(u8));
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

void write_fcrypt_file(FCRYPT_CTX *ctx, FILE *fptr, u8 *data) {
    u8 *ciphertext = (u8 *)malloc(ctx->data_size);
    encrypt_data(ctx, data, ciphertext);

    size_t total_len = 44 + ctx->data_size;

    u8 *buffer = (u8 *)malloc(total_len);

    memcpy(buffer, ctx->password_hash, 32);
    memcpy(buffer+32, ctx->nonce, 12);
    memcpy(buffer+44, ciphertext, ctx->data_size);

    fwrite(buffer, 1, total_len, fptr);
    free(buffer);
}


u8 *read_fcrypt_file(FCRYPT_CTX *ctx, FILE *fptr) {
    /**
     * 1. get SHA3(password, 256) and compare to ctx->password_hash
     * 2. if password is correct derive key from password else return
     * 3. copy nonce to ctx->nonce
     * 4. decrypt file
     * 5. write decrypted data to file
     */
    fseek(fptr, 0, SEEK_END);
    ctx->data_size = ftell(fptr) - 44;
    fseek(fptr, 0, SEEK_SET);

    u8 *plaintext = (u8 *)malloc(ctx->data_size);

    u8 *password_from_file = (u8 *)malloc(32);
    fread(password_from_file, sizeof(u8), 32, fptr);

    if(memcmp(password_from_file, ctx->password_hash, 32) == 0) {
        u8 *buffer = (u8 *)malloc(ctx->data_size);
        fread(buffer, sizeof(u8), ctx->data_size, fptr);

        memcpy(ctx->nonce, buffer, 12);

        decrypt_data(ctx, buffer+12, plaintext);

        return plaintext;
    } else {
        return NULL;
    }
}

void init_fcrypt_ctx(FCRYPT_CTX *ctx, u8 *password, u8 password_len, u32 *nonce) {
    /**
     * 1. set nonce in ctx
     * 2. derive key from password
     * 3. set key in ctx
     */
    u8 key[KEY_SIZE*4];
    u32 lkey[KEY_SIZE];
    u8 processed_password[32];
    
    // memcpy(ctx->nonce, nonce, NONCE_SIZE);
    // memcpy doesn't work
    ctx->nonce[0] = nonce[0];
    ctx->nonce[1] = nonce[1];
    ctx->nonce[2] = nonce[2];

    sha3(password, password_len, ctx->password_hash, 32);

    process_password(password, password_len, processed_password);

    pbkdf(processed_password, 32, 0, key, 32);

    for (size_t i = 0; i < 8; i ++) {
        u8_to_u32(&key[i * 4], &lkey[i]);
    }

    memcpy(ctx->key, lkey, KEY_SIZE);
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
