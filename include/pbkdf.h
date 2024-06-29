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

#include <openssl/evp.h>
#include <string.h>

#include "types.h"

extern u32 NONCE[3]; 
/**
 * nonce is not really nonce here, but is used only because chacha requires it
 * I think it can be fixed because we are not reusing keys (this is user password)
*/

void pbkdf(char *password, size_t password_len, u8 *key, size_t key_size);

void process_password(u8 *password, size_t password_len, u8 *processed);
void u8_to_u32(u8 *src, u32 *dst);

#endif /* _PBKDF_H */