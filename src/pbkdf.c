#include "pbkdf.h"

u32 NONCE[3] = {0x14159265, 0x35897932, 0x38462643}; // pi

void pbkdf(char *password, size_t password_len, u8 *key, size_t key_size) {
    u8 salt[] = {
        0x61, 0x20, 0x6e, 0x6f,
        0x74, 0x68, 0x69, 0x6e,
        0x67, 0x2d, 0x75, 0x70,
        0x2d, 0x6d, 0x79, 0x2d,
        0x73, 0x6c, 0x65, 0x65,
        0x76, 0x65, 0x20, 0x73,
        0x61, 0x6c, 0x74};
    if (PKCS5_PBKDF2_HMAC(password, password_len, salt, sizeof(salt), 4096, EVP_sha1(), key_size, key) == 0) {
        fprintf(stderr, "error deriving key!");
        key = NULL;
    }
}

void process_password(u8 *password, size_t password_len, u8 *processed) { 
    /**
     * Function to make key for kdf from password
     * if password is shorter or equal to 32 characters then pad it with zeros
     */
    if (password_len <= 32) {
        memcpy(processed, password, password_len);
        size_t pad_value = 32-password_len;
        for (size_t i = password_len; i < 32; i++) {
            processed[i] = pad_value;
        }
    } else {
        /**
         * idk why would you use password longer than 32 characters
         * but you can :)
         */
        memcpy(processed, password, 32);
        for (size_t i=32; i<password_len; i++) {
            processed[(i-32) % 32] ^= password[i];
        }
    }
}

inline void u8_to_u32(u8 *src, u32 *dst) {
    *dst = ((u32)src[0]) | ((u32)src[1] << 8) | ((u32)src[2] << 16) | ((u32)src[3] << 24);
}
