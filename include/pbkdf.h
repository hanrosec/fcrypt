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

void pbkdf(char *password, size_t password_len, u8 *key, size_t key_size);
void sha3_256(const unsigned char *data, size_t data_len, unsigned char *hash);

#endif /* _PBKDF_H */