/**
 * ChaCha20-based Key derivation function
 * Counter is set to 0 as default, but it can be arbitrary
 * Counter will be incresed if derived key need to be longer than 16 bytes
 * Nonce is fixed
 * Key is password (max 32 characters) (must be padded to size of 32 characters)
 * Derived key is first n number of bytes of key schedule
 */

#ifndef _PBKDF_H
#define _PBKDF_H

#include "chacha.h"

extern uint32_t NONCE[3]; 
/**
 * nonce is not really nonce here, but is used only because chacha requires it
 * I think it can be fixed because we are not reusing keys (this is user password)
*/

void pbkdf(uint8_t *password, uint8_t password_len, uint32_t counter, uint8_t *key, size_t key_size);

void process_password(uint8_t *password, size_t password_len, uint8_t *processed);
void u8_to_u32(uint8_t *src, uint32_t *dst);

#endif /* _PBKDF_H */