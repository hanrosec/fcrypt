#ifndef _PBKDF_H
#define _PBKDF_H

#include <openssl/evp.h>
#include <string.h>

#include "types.h"

void pbkdf(char *password, size_t password_len, u8 *key, size_t key_size);
void sha3_256(const unsigned char *data, size_t data_len, unsigned char *hash);

#endif /* _PBKDF_H */