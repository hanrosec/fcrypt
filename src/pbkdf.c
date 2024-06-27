#include "pbkdf.h"

u32 NONCE[3] = {0x14159265, 0x35897932, 0x38462643}; // pi

void pbkdf(u8 *password, u8 password_len, u32 counter, u8 *key, size_t key_size) {
    CHACHA_CTX ctx;
    
    u8 processed_password[password_len];
    u32 key_for_chacha[8];
    u32 keystream32[key_size];
    u8 keystream8[key_size*8];
    
    // make password correct length
    process_password(password, password_len, processed_password);

    /**
    * ? use some hash function to increase entropy 
    * ? must be different than hash function used in encrypted file
    */

    // convert password from u8 to u32 for chacha
    for (size_t i = 0; i < 8; i ++) {
        u8_to_u32(&processed_password[i * 4], &key_for_chacha[i]);
    }

    init_chacha_ctx(&ctx, key_for_chacha, NONCE, counter);

    // generate chacha keystream
    chacha_generate_keystream(&ctx, 1, keystream32);
    
    // use only desired length of previously generated key
    serialize(keystream32, keystream8);
    memcpy(key, keystream8, key_size);
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
