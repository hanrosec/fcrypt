# fcrypt

## Usage

TODO

## Encryption

1. get password from user
2. initialize ctx:
    1. derive key and add it to ctx
    2. generate nonce and add it to ctx
3. read data from file
4. encrypt data
5. create file header
6. file creation:
    1. write header
    2. write encrypted data

## Decryption

1. read first 32 (u8) bytes
2. get password from user
3. check if password is correct: SHA3(password, 256) == first 32 bytes of file
4. read next 12 (u8) bytes and write it to ctx as nonce
5. read rest of file
6. decrypt file
7. write decrypted data to file
