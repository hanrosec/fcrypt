#ifndef _PBKDF_H
#define _PBKDF_H

#include <openssl/evp.h>
#include <string.h>

#include "types.h"

void pbkdf(char *password, size_t password_len, u8 *key, size_t key_size);

#endif /* _PBKDF_H */