#include "fcrypt.h"

// u8 *read_raw(FCRYPT_CTX *ctx, FILE *fptr) {
//     // get size of file
//     fseek(fptr, 0, SEEK_END);
//     ctx->data_size = ftell(fptr);
//     fseek(fptr, 0, SEEK_SET);

//     u8 *buffer = (u8 *)malloc(ctx->data_size);
//     if(buffer == NULL) {
//         fprintf(stderr, "error allocating memory\n");
//         return NULL;
//     }

//     char ch;
//     size_t i = 0;
//     do {
//         ch = getc(fptr);
//         buffer[i++] = ch;
//     } while(ch != EOF);

//     return buffer;
// }

u8 *read_raw(FCRYPT_CTX *ctx, FILE *fptr) {
    // get size of file
    fseek(fptr, 0, SEEK_END);
    ctx->data_size = ftell(fptr);
    fseek(fptr, 0, SEEK_SET);

    u8 *buffer = (u8 *)malloc(ctx->data_size + 1); // +1 for null-terminator
    if(buffer == NULL) {
        fprintf(stderr, "error allocating memory\n");
        return NULL;
    }

    int ch;
    size_t i = 0;
    while((ch = getc(fptr))!= EOF) {
        if(i >= ctx->data_size) {
            fprintf(stderr, "buffer overflow\n");
            free(buffer);
            return NULL;
        }
        buffer[i++] = (u8)ch;
    }

    buffer[i] = '\0'; // null-terminate the buffer

    return buffer;
}

void write_fcrypt_file(FCRYPT_CTX *ctx, FILE *fptr, u8 *data) {
    u8 *ciphertext = (u8 *)malloc(ctx->data_size);
    encrypt_data(ctx, data, ctx->data_size, ciphertext);

    size_t total_len = 44 + ctx->data_size;

    u8 *buffer = (u8 *)malloc(total_len);

    memcpy(buffer, ctx->password_hash, 32);
    memcpy(buffer+32, ctx->iv, 12);
    memcpy(buffer+44, ciphertext, ctx->data_size);

    fwrite(buffer, 1, total_len, fptr);
    free(buffer);
}

u8 *read_fcrypt_file(FCRYPT_CTX *ctx, FILE *fptr) {
    /**
     * 1. get SHA3(password, 256) and compare to ctx->password_hash
     * 2. if password is correct derive key from password else return
     * 3. copy iv to ctx->iv
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

        memcpy(ctx->iv, buffer, 12);

        // decrypt_data(ctx, buffer+12, plaintext);

        return plaintext;
    } else {
        return NULL;
    }
}

void init_fcrypt_ctx(FCRYPT_CTX *ctx, char *password, u8 password_len, u8 *iv) {
    /**
     * 1. set iv in ctx
     * 2. derive key from password
     * 3. set key in ctx
     */
    u8 key[sizeof(ctx->key)];
    
    // memcpy(ctx->iv, iv, iv_SIZE);
    // memcpy doesn't work
    memcpy(ctx->iv, iv, sizeof(ctx->iv));

    sha3(password, password_len, ctx->password_hash, 32);

    pbkdf(password, password_len, key, 32);

    memcpy(ctx->key, key, sizeof(ctx->key));
}

int encrypt_data(FCRYPT_CTX *ctx, u8 *plaintext, int plaintext_len, u8 *ciphertext) {
    EVP_CIPHER_CTX *evp_ctx = EVP_CIPHER_CTX_new();
    
    if(evp_ctx == NULL) {
        fprintf(stderr, "error while creating EVP_CIPHER_CTX!\n");
        EVP_CIPHER_CTX_free(evp_ctx);
        return -1;
    }

    int len;
    int ciphertext_len = 0;
    int chunk_size = 16; // AES block size in bytes

    if (EVP_EncryptInit_ex(evp_ctx, EVP_aes_256_ctr(), NULL, ctx->key, ctx->iv) != 1) {
        fprintf(stderr, "error while initializing encryption!\n");
        EVP_CIPHER_CTX_free(evp_ctx);
        return -1;
    }

    for (int i = 0; i < plaintext_len; i += chunk_size) {
        int chunk_len = plaintext_len - i;
        if (chunk_len > chunk_size) {
            chunk_len = chunk_size;
        }
        // print_u8(ciphertext + ciphertext_len, 16);
        // printf("%d\n", chunk_len);
        if (EVP_EncryptUpdate(evp_ctx, ciphertext + ciphertext_len, &len, plaintext + i, chunk_len) != 1) {
            fprintf(stderr, "error while encrypting!\n");
            EVP_CIPHER_CTX_free(evp_ctx);
            return -1;
        }
        ciphertext_len += len;
    }

    if (EVP_EncryptFinal_ex(evp_ctx, ciphertext + ciphertext_len, &len) != 1) {
        fprintf(stderr, "error while finalizing encryption!\n");
        EVP_CIPHER_CTX_free(evp_ctx);
        return -1;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(evp_ctx);

    return ciphertext_len;
}

int decrypt_data(FCRYPT_CTX *ctx, u8 *ciphertext, int ciphertext_len, u8 *plaintext) {
    EVP_CIPHER_CTX *evp_ctx = EVP_CIPHER_CTX_new();

    if(evp_ctx == NULL) {
        fprintf(stderr, "error while creating EVP_CIPHER_CTX!\n");
        EVP_CIPHER_CTX_free(evp_ctx);
        return -1;
    }

    int len;
    int plaintext_len = 0;
    int chunk_size = 16; // AES block size in bytes

    if(EVP_DecryptInit_ex(evp_ctx, EVP_aes_256_ctr(), NULL, ctx->key, ctx->iv) != 1) {
        fprintf(stderr, "error while initializing decryption!\n");
        EVP_CIPHER_CTX_free(evp_ctx);
        return -1;
    }

    for (int i = 0; i < ciphertext_len; i += chunk_size) {
        int chunk_len = ciphertext_len - i;
        if (chunk_len > chunk_size) {
            chunk_len = chunk_size;
        }

        if (EVP_DecryptUpdate(evp_ctx, plaintext + plaintext_len, &len, ciphertext + i, chunk_len) != 1) {
            fprintf(stderr, "error while decrypting data!\n");
            EVP_CIPHER_CTX_free(evp_ctx);
            return -1;
        }
        plaintext_len += len;
    }

    if (EVP_DecryptFinal_ex(evp_ctx, plaintext + plaintext_len, &len) != 1) {
        fprintf(stderr, "error while finalizing decryption!\n");
        EVP_CIPHER_CTX_free(evp_ctx);
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(evp_ctx);

    return plaintext_len;
}