#include "fcrypt.h"

u8 *read_raw(FCRYPT_CTX *ctx, FILE *fptr) {
    // get size of file
    fseek(fptr, 0, SEEK_END);
    ctx->data_size = ftell(fptr);
    fseek(fptr, 0, SEEK_SET);

    u8 *buffer = (u8 *)calloc(ctx->data_size + 1, 1);
    if(buffer == NULL) {
        perror("error allocating memory\n");
        return NULL;
    }

    int ch;
    int i = 0;
    while((ch = getc(fptr))!= EOF) {
        if(i >= ctx->data_size) {
            perror("buffer overflow\n");
            free(buffer);
            return NULL;
        }
        buffer[i++] = (u8)ch;
    }

    buffer[i] = '\0';

    return buffer;
}

void write_fcrypt_file(FCRYPT_CTX *ctx, FILE *fptr, u8 *data) {
    u8 *ciphertext = (u8 *)malloc(ctx->data_size);
    encrypt_data(ctx, data, ctx->data_size, ciphertext);

    size_t total_len = 48 + ctx->data_size;

    u8 *buffer = (u8 *)malloc(total_len);

    memcpy(buffer, ctx->password_hash, 32);
    memcpy(buffer+32, ctx->iv, 16);
    memcpy(buffer+48, ciphertext, ctx->data_size);

    fwrite(buffer, 1, total_len, fptr);
    free(ciphertext);
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
    ctx->data_size = ftell(fptr) - 32;
    fseek(fptr, 0, SEEK_SET);
    
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wunused-result" 

    u8 *password_from_file = (u8 *)calloc(32, sizeof(u8));
    fread(password_from_file, sizeof(u8), 32, fptr);

    if(memcmp(password_from_file, ctx->password_hash, 32) == 0) {
        free(password_from_file);
        u8 *plaintext = (u8 *)calloc(ctx->data_size, sizeof(u8));
        u8 *ciphertext = (u8 *)calloc(ctx->data_size, sizeof(u8));

        fread(ciphertext, sizeof(u8), ctx->data_size, fptr);
        
        #pragma GCC diagnostic pop 

        memcpy(ctx->iv, ciphertext, 16);

        decrypt_data(ctx, ciphertext+16, ctx->data_size-16, plaintext); // someday i will find out why this bug occurs
        
        free(ciphertext);
        return plaintext;
    } else {
        free(password_from_file);
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
    memcpy(ctx->iv, iv, sizeof(ctx->iv));

    sha3_256((const unsigned char *)password, password_len, ctx->password_hash);
    pbkdf(password, password_len, key, 32);

    memcpy(ctx->key, key, sizeof(ctx->key));
}

int encrypt_data(FCRYPT_CTX *ctx, u8 *plaintext, int plaintext_len, u8 *ciphertext) {
    EVP_CIPHER_CTX *evp_ctx;
    
    if((evp_ctx = EVP_CIPHER_CTX_new()) == NULL) {
        perror("error while creating EVP_CIPHER_CTX!\n");
        EVP_CIPHER_CTX_free(evp_ctx);
        exit(EXIT_FAILURE);
    }

    int len;
    int ciphertext_len = 0;
    int chunk_size = 16;

    if (1 != EVP_EncryptInit_ex(evp_ctx, EVP_aes_256_ctr(), NULL, ctx->key, ctx->iv)) {
        perror("error while initializing encryption!\n");
        EVP_CIPHER_CTX_free(evp_ctx);
        exit(EXIT_FAILURE);
    }

    if(verbose) printf("encrypting data... (0/%d) chunks", (int)(plaintext_len/chunk_size));
    for (int i = 0; i < plaintext_len; i += chunk_size) {
        int chunk_len = plaintext_len - i;
        if (chunk_len > chunk_size) {
            chunk_len = chunk_size;
        }
        if (1 != EVP_EncryptUpdate(evp_ctx, ciphertext + ciphertext_len, &len, plaintext + i, chunk_len)) {
            perror("error while encrypting!\n");
            EVP_CIPHER_CTX_free(evp_ctx);
            exit(EXIT_FAILURE);
        }
        ciphertext_len += len;
        if(verbose) printf("\rencrypting data... (%d/%d) chunks", (int)(i/chunk_size), (int)(plaintext_len/chunk_size)-1);
        fflush(stdout);
    }
    if(verbose) printf("\nsuccessfully encrypted data!\n");

    if (1 != EVP_EncryptFinal_ex(evp_ctx, ciphertext + ciphertext_len, &len)) {
        perror("error while finalizing encryption!\n");
        EVP_CIPHER_CTX_free(evp_ctx);
        exit(EXIT_FAILURE);
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(evp_ctx);

    return ciphertext_len;
}

int decrypt_data(FCRYPT_CTX *ctx, u8 *ciphertext, int ciphertext_len, u8 *plaintext) {
    EVP_CIPHER_CTX *evp_ctx;

    if((evp_ctx = EVP_CIPHER_CTX_new()) == NULL) {
        perror("error while creating EVP_CIPHER_CTX!\n");
        EVP_CIPHER_CTX_free(evp_ctx);
        exit(EXIT_FAILURE);
    }

    int len;
    int plaintext_len = 0;
    int chunk_size = 16;

    if(1 != EVP_DecryptInit_ex(evp_ctx, EVP_aes_256_ctr(), NULL, ctx->key, ctx->iv)) {
        perror("error while initializing decryption!\n");
        EVP_CIPHER_CTX_free(evp_ctx);
        exit(EXIT_FAILURE);
    }

    if(verbose) printf("decrypting data... (0/%d) chunks", (int)(plaintext_len/chunk_size));
    for (int i = 0; i < ciphertext_len; i += chunk_size) {
        int remaining_bytes = ciphertext_len - i;
        int chunk_len = (remaining_bytes < chunk_size) ? remaining_bytes : chunk_size;

        if (1 != EVP_DecryptUpdate(evp_ctx, plaintext + plaintext_len, &len, ciphertext + i, chunk_len)) {
            perror("error while decrypting data!\n");
            EVP_CIPHER_CTX_free(evp_ctx);
            exit(EXIT_FAILURE);
        }
        plaintext_len += len;
        if(verbose) printf("\rdecrypting data... (%d/%d) chunks", (int)(i/chunk_size), (int)(ciphertext_len/chunk_size)-1);
        fflush(stdout);
    }
    if(verbose) printf("\nsuccessfully decrypted data!\n");


    if (1 != EVP_DecryptFinal_ex(evp_ctx, plaintext + plaintext_len, &len)) {
        perror("error while finalizing decryption!\n");
        EVP_CIPHER_CTX_free(evp_ctx);
        exit(EXIT_FAILURE);
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(evp_ctx);

    return plaintext_len;
}

void sha3_256(const unsigned char *data, size_t data_len, unsigned char *hash) {
    EVP_MD_CTX *mdctx;
    if((mdctx = EVP_MD_CTX_new()) == NULL) {
        perror("EVP_MD_CTX_new");
        exit(EXIT_FAILURE);
    }

    if(1 != EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL)) {
        perror("EVP_DigestInit_ex");
        exit(EXIT_FAILURE);
    }

    if(1 != EVP_DigestUpdate(mdctx, data, data_len)) {
        perror("EVP_DigestUpdate");
        exit(EXIT_FAILURE);
    }

    u32 hash_len;
    if(1 != EVP_DigestFinal_ex(mdctx, hash, &hash_len)) {
        perror("EVP_DigestFinal_ex");
        exit(EXIT_FAILURE);
    }

    EVP_MD_CTX_free(mdctx);
}