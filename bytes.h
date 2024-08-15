#ifndef BYTES_H
#define BYTES_H
#define MAX_BYTE 128
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

typedef unsigned char byte;

// byte functions
void print_bytes(const byte * bytes, int len);
void print_hex(const byte * hex, int len);
void print_b64(const byte * b64, int len);
byte * alloc_bytes(int len);
void print(const byte * string, int len);
int cat(byte * d1, int l1, byte * d2, int l2, byte * output);

// string to byte functions
int from_hex(char * hex, byte * bytes);
int from_b64(char * b64, byte * bytes);
int from_string(char * str, byte * bytes);
void to_string(byte * bytes, int len, unsigned char * str);

void XOR(byte * b1, byte * b2, byte * output, int len);
float english_score(byte * b, int len);
void single_byte_xor(byte * b, int len, byte key, byte * output);
unsigned char single_byte_xor_decrypt(byte * b, int len, byte * output);
void repeating_key_xor(byte * b, byte * key, int len, int keylen, byte * output);
void repeating_key_xor_decrypt(byte * b, int len, byte * output);

// openssl
int aes_128_ecb_decrypt(byte * input, int len, byte * key, int keylen, byte * output);
#endif
