#include "fcrypt.h"

void read_data(FCRYPT_CTX *ctx, FILE *fptr) {
    if (fptr == NULL) {
        fprintf(stderr, "Failed to open file");
        return;
    }

    // Get size of file
    fseek(fptr, 0, SEEK_END);
    ctx->data_size = ftell(fptr);
    fseek(fptr, 0, SEEK_SET);

    // Allocate buffer for reading file content
    uint8_t *buffer = (uint8_t *)malloc(ctx->data_size);
    if (buffer == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(fptr);
        return;
    }

    // Read file content into buffer
    size_t bytes_read = fread(buffer, 1, ctx->data_size, fptr);
    if (bytes_read != ctx->data_size) {
        fprintf(stderr, "Failed to read file\n");
        free(buffer);
        fclose(fptr);
        return;
    }

    // Reallocate memory for ctx->data
    uint8_t *new_data = (uint8_t *)realloc(ctx->data, ctx->data_size);
    if (new_data == NULL) {
        fprintf(stderr, "Memory reallocation failed\n");
        free(buffer);
        fclose(fptr);
        return;
    }

    ctx->data = new_data;

    // Copy buffer content to ctx->data
    memcpy(ctx->data, buffer, ctx->data_size);

    // Free buffer and close file
    free(buffer);
}

void init_fcrypt_ctx(FCRYPT_CTX *ctx, uint8_t *password, uint8_t password_len, uint32_t *nonce)
{
    /**
     * 1. derive key from password
     * 2. set key in ctx
     * 3. set nonce in ctx
     */
    uint8_t key[KEY_SIZE*4];
    uint32_t lkey[KEY_SIZE];
    uint8_t processed_password[32];
    
    process_password(password, password_len, processed_password);

    pbkdf(processed_password, 32, 0, key, 32);

    for (size_t i = 0; i < 8; i ++) {
        u8_to_u32(&key[i * 4], &lkey[i]);
    }

    memcpy(ctx->key, lkey, KEY_SIZE);
    memcpy(ctx->nonce, nonce, NONCE_SIZE);
    ctx->data_size = 0;
}

void generate_nonce(uint32_t *nonce) {
    uint8_t random_bytes[NONCE_SIZE*4];
    for (size_t i=0; i<NONCE_SIZE*4; i++) {
        random_bytes[i] = rand() % 256;
    }

    for (size_t i = 0; i < NONCE_SIZE; i++) {
        u8_to_u32(&random_bytes[i*4], &nonce[i]);
    }
}
