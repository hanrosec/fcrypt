#include "..\include\pbkdf.h"

uint32_t NONCE[3] = {0x14159265, 0x35897932, 0x38462643}; // pi

void pbkdf(uint8_t *password, uint8_t password_len, uint32_t counter, uint8_t *key, size_t key_size) {
    CHACHA_CTX ctx;
    uint8_t processed_password[password_len];
    
    // make password correct length
    process_password(password, password_len, processed_password);

    uint32_t key_for_chacha[8];

    // TODO use some hash function to increase entropy

    // convert password from u8 to u32 for chacha
    for (size_t i = 0; i < 8; i ++) {
        u8_to_u32(&processed_password[i * 4], &key_for_chacha[i]);
    }

    init_chacha_ctx(&ctx, key_for_chacha, NONCE, counter);

    uint32_t keystream32[key_size];

    // generate chacha keystream
    chacha_generate_keystream(&ctx, 1, keystream32);
    uint8_t keystream8[key_size*8];
    
    // use only desired length of previously generated key
    serialize(keystream32, keystream8);
    memcpy(key, keystream8, key_size);
}

void process_password(uint8_t *password, size_t password_len, uint8_t *processed) { 
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
            processed[i-32] ^= password[i];
        }
    }
}

inline void u8_to_u32(uint8_t *src, uint32_t *dst) {
    *dst = ((uint32_t)src[0]) | ((uint32_t)src[1] << 8) | ((uint32_t)src[2] << 16) | ((uint32_t)src[3] << 24);
}
