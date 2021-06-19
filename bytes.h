#ifndef BYTES_H
#define BYTES_H
#define MAX_BYTE 128
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
struct byte{
    unsigned char data;
};

//byte functions
void print_bytes(const struct byte * bytes, int len);
void print_hex(const struct byte * hex, int len);
void print_b64(const struct byte * b64, int len);
struct byte * alloc_bytes(int len);
void print(const struct byte * string, int len);
int cat(struct byte * d1, int l1, struct byte * d2, int l2, struct byte * output);

//string to byte functions
int from_hex(char * hex, struct byte * bytes);
int from_b64(char * b64, struct byte * bytes);
int from_string(char * str, struct byte * bytes);
void to_string(struct byte * bytes, int len, unsigned char * str);

void XOR(struct byte * b1, struct byte * b2, struct byte * output, int len);
float english_score(struct byte * b, int len);
void single_byte_xor(struct byte * b, int len, struct byte key, struct byte * output);
unsigned char single_byte_xor_decrypt(struct byte * b, int len, struct byte * output);
void repeating_key_xor(struct byte * b, struct byte * key, int len, int keylen, struct byte * output);
void repeating_key_xor_decrypt(struct byte * b, int len, struct byte * output);

//openssl
int aes_128_ecb_decrypt(struct byte * input, int len, struct byte * key, int keylen, struct byte * output);
#endif
