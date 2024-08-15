#include <stdio.h>
#include <string.h>
#include "bytes.h"

void print_bytes (const byte * bytes, int len) {
    for (int i = 0; i < len; i++) {
        byte temp;
        temp = bytes[i];
        for (int j = 1; j <= MAX_BYTE; j *= 2) {
            if (temp - MAX_BYTE / j >= 0) {
                printf("1");
                temp -= MAX_BYTE / j;
            } else {
                printf("0");
            }
        }
        printf(" ");
    }
}

void print_hex_helper (byte b) {
    if(b >= 0 && b <= 9) printf("%c", b + '0');
    else if(b >= 10 && b <= 15) printf("%c", b + 'a' - 10);
    else printf("?"); // prints if invalid hex        
}

void print_hex (const byte * hex, int len) {
    for (int i = 0; i < len; i++) {
        byte temp1;
        temp1 = hex[i] << 4;
        temp1 = temp1 >> 4;
        byte temp2;
        temp2 = hex[i] >> 4;
        print_hex_helper(temp2); 
        print_hex_helper(temp1);  
    }
}

unsigned char print_b64_helper (unsigned char b) {
    if (b >=0 && b <= 25) return b + 'A';
    else if (b >= 26 && b <= 51) return b + 'a' - 26;
    else if (b >= 52 && b <= 61) return b + '0' - 52;
    else if (b == 62) return '+';
    else if (b == 63) return '/';
    else return '?'; // if invalid b64
}

void print_b64 (const byte * b64, int len) {
    for (int i = 0; i < len - (len % 3); i += 3) {
        byte temp1;
        temp1 = b64[i] >> 2;
        byte temp2;
        temp2 = b64[i] << 6;
        temp2 = temp2 >> 2;
        temp2 += b64[i + 1] >> 4;
        byte temp3;
        temp3 = b64[i + 1] << 4;
        temp3 = temp3 >> 2;
        temp3 += b64[i + 2] >> 6;
        byte temp4;
        temp4 = b64[i + 2] << 2;
        temp4 = temp4 >> 2;
        printf("%c%c%c%c", print_b64_helper(temp1), print_b64_helper(temp2), 
               print_b64_helper(temp3), print_b64_helper(temp4));
    }
    if (len % 3 == 1) {
        byte temp1;
        temp1 = b64[len - 1] >> 2;
        byte temp2;
        temp2 = b64[len - 1] << 6;
        temp2 = temp2 >> 2;
        printf("%c%c%c%c", print_b64_helper(temp1),
               print_b64_helper(temp2), '=', '=');
    } else if(len % 3 == 2) {
        byte temp1;
        temp1 = b64[len - 2] >> 2;
        byte temp2;
        temp2 = b64[len - 2] << 6;
        temp2 = temp2 >> 2;
        temp2 += b64[len - 1] >> 4;
        byte temp3;
        temp3 = b64[len - 1] << 4;
        temp3 = temp3 >> 2;
        printf("%c%c%c%c", print_b64_helper(temp1),
               print_b64_helper(temp2), print_b64_helper(temp3), '=');
    }
}

byte * alloc_bytes (int len) {
    return (byte *)malloc(len * sizeof(byte));
}

void print (const byte * string, int len) {
    for (int i = 0; i < len; i++) {
        printf("%c", string[i]);
    }
}   

int cat (byte * d1, int l1, byte * d2, int l2, byte * output) {
    memcpy(output, d1, l1);
    memcpy(output + l1, d2, l2);
    return l1 + l2;
}
unsigned char from_hex_helper (unsigned char hex) {
    if (hex >= 'a' && hex <= 'f') return hex - 'a' + 10;
    else if (hex >= '0' && hex <= '9') return hex - '0';
    else return '?'; // if invalid hex
}
int from_hex (char * hex, byte * bytes) {
    int counter = 0;
    for (int i = 0; i < strlen(hex); i += 2) {
        byte temp;
        temp = from_hex_helper(hex[i]) << 4;
        temp += from_hex_helper(hex[i+1]);
        bytes[counter] = temp;
        counter++;
    }
    return counter;
}

unsigned char from_b64_helper (unsigned char b) {
    if (b >= 'A' && b <= 'Z') return b - 'A';
    else if (b >= 'a' && b <= 'z') return b - 'a' + 26;
    else if (b >= '0' && b <= '9') return b - '0' + 52;
    else if (b == '+') return 62;
    else if (b == '/') return 63;
    else return '?'; // invalid b64 
}

int from_b64 (char * b64, byte * bytes) {
    int len = strlen(b64);
    int counter = 0;
    if(b64[len - 1] == '=') len -= 4;
    for (int i = 0;  i < len; i += 4) {
        byte temp1;
        temp1 = from_b64_helper(b64[i]) << 2;
        temp1 += from_b64_helper(b64[i+1]) >> 4;
        byte temp2;
        temp2 = from_b64_helper(b64[i+1]) << 4;
        temp2 += from_b64_helper(b64[i+2]) >> 2;
        byte temp3;
        temp3 = from_b64_helper(b64[i+2]) << 6;
        temp3 += from_b64_helper(b64[i+3]);
        bytes[counter] = temp1;
        counter++;
        bytes[counter] = temp2;
        counter++;
        bytes[counter] = temp3;
        counter++;
    }

    len = strlen(b64);
    if (b64[len - 1] == '=' && b64[len - 2] == '=') {
        byte temp1;
        temp1 = from_b64_helper(b64[len - 4]) << 2;
        temp1 += from_b64_helper(b64[len - 3]) >> 4;
        bytes[counter] = temp1;
        counter++;
    } else if (b64[len - 1] == '=') {
        byte temp1;
        temp1 = from_b64_helper(b64[len - 4]) << 2;
        temp1 += from_b64_helper(b64[len - 3]) >> 4;
        byte temp2;
        temp2 = from_b64_helper(b64[len - 3]) << 4;
        temp2 += from_b64_helper(b64[len - 2]) >> 2;
        bytes[counter] = temp1;
        counter++;
        bytes[counter] = temp2;
        counter++;
    }


    return counter;
}

int from_string (char * str, byte * bytes) {
    for (int i = 0; i < strlen(str); i++) {
        bytes[i] = str[i];
    }

    return strlen(str);
}

void to_string (byte * bytes, int len, unsigned char * str) {
    for (int i = 0; i < len; i++) {
        str[i] = bytes[i];
    }
}

void XOR (byte * b1, byte * b2, byte * output, int len) {
    for (int i = 0; i < len; i++) {
        output[i] = b1[i] ^ b2[i];
    }
}

float english_score (byte * b, int len) {
    float ret = 0.0;
    float scores[256] = {0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000,
0.000000, 0.000000, 0.000000, 0.002833, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000,
0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000,
0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.190423, 0.000590,
0.000095, 0.000000, 0.000000, 0.000000, 0.000000, 0.005477, 0.000551, 0.000561, 0.000000,
0.000000, 0.012836, 0.002253, 0.009756, 0.000000, 0.000067, 0.000371, 0.000114, 0.000133,
0.000133, 0.000019, 0.000038, 0.000057, 0.000029, 0.000162, 0.000723, 0.001312, 0.000000,
0.000000, 0.000000, 0.000352, 0.000000, 0.001455, 0.003632, 0.000238, 0.000647, 0.001027,
0.001198, 0.001369, 0.001921, 0.003537, 0.000048, 0.000133, 0.000418, 0.001217, 0.000618,
0.000799, 0.000380, 0.000000, 0.000789, 0.001721, 0.003166, 0.000105, 0.000086, 0.000922,
0.000010, 0.000437, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.001673, 0.000000,
0.059788, 0.014567, 0.014681, 0.037054, 0.095159, 0.018151, 0.015746, 0.045022, 0.048084,
0.000485, 0.006275, 0.033450, 0.016098, 0.052857, 0.060007, 0.010668, 0.000666, 0.044775,
0.043814, 0.067081, 0.018779, 0.007359, 0.016126, 0.000770, 0.015689, 0.000247, 0.000000,
0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000,
0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000,
0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000,
0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000,
0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000,
0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000,
0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000,
0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000,
0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000,
0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000,
0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000,
0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000,
0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000,
0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000,
0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000};
    for (int i = 0; i < len; i++) {
        ret += scores[b[i]];
    }
    return ret;
}

void single_byte_xor (byte * b, int len, byte key, byte * output) {
    for (int i = 0; i < len; i++) {
        output[i] = b[i] ^ key;
    }
}

unsigned char single_byte_xor_decrypt (byte * b, int len, byte * output) {
    float max = 0.0;
    byte * temp = alloc_bytes(len);
    unsigned char ret;
    for (unsigned char i = 0; i < MAX_BYTE; i++) {
        byte key;
        key = i;
        single_byte_xor(b, len, key, temp);
        float curr = english_score(temp, len);
        if (curr > max) {
            max = curr;
            memcpy(output, temp, len);
            ret = i;
        }
    }
    free(temp);
    return ret;
}

void repeating_key_xor (byte * b, byte * key, int len, int keylen, byte * output) {
    for(int i = 0; i < len; i++){
        output[i] = b[i] ^ key[i % keylen];
    }
}

int hamming (byte * b1, byte * b2, int len) {
    int ret = 0;
    for (int i = 0; i < len; i++) {
        byte temp;
        temp = b1[i] ^ b2[i];
        for (int j = 1; j <= MAX_BYTE; j *= 2) {
            if (temp - MAX_BYTE / j >= 0) {
                ret++;
                temp -= MAX_BYTE / j;
            }
        }
    }
    return ret;
}

void repeating_key_xor_decrypt (byte * b, int len, byte * output) {
    byte * temp1 = alloc_bytes(len);
    byte * temp2 = alloc_bytes(len);
    byte * temp3 = alloc_bytes(len);
    byte * temp4 = alloc_bytes(len);
    int min[3] = {1000, 1000, 1000};
    int keysize[3] = {0, 0, 0};
     
    for (int i = 2; i < len / 4; i++) {
        memcpy(temp1, b, i);
        memcpy(temp2, b+i, i);
        memcpy(temp3, b+(i*2), i);
        memcpy(temp4, b+(i*3), i);
        int ham = hamming(temp1, temp2, i);
        ham += hamming(temp1, temp3, i);
        ham += hamming(temp1, temp4, i);
        ham += hamming(temp2, temp3, i);
        ham += hamming(temp2, temp4, i);
        ham += hamming(temp3, temp4, i);
        ham /= (i*6);
        for (int j = 0; j < 3; j++) {
            if (ham < min[j]) {
                min[j] = ham;
                keysize[j] = i;
                break;
            } 
        }
    }

    float max = 0;
    for (int k = 0; k < 3; k++) {
        byte * key = alloc_bytes(keysize[k]);
        byte * trash = alloc_bytes(len);
        byte * trash2 = alloc_bytes(len);
        for (int i = 0; i < keysize[k]; i++) {
            int counter = 0;
            for (int j = i; j < len; j += keysize[k]) {
                trash[counter] = b[j];
                counter++;
            }
            key[i] = single_byte_xor_decrypt(trash, counter, trash2);
        }
        repeating_key_xor(b, key, len, keysize[k], trash);
        float score = english_score(trash, len);
        if(score > max) {
            max = score;
            memcpy(output, trash, len);
        }
        free(key);
        free(trash);
        free(trash2);
    }
    free(temp1);
    free(temp2);
    free(temp3);
    free(temp4);
}

int aes_128_ecb_decrypt (byte * input, int len, byte * key, int keylen, byte * output) {
    unsigned char * skey = (unsigned char *)malloc(keylen * sizeof(unsigned char));
    to_string(key, keylen, skey);
    
    unsigned char * sinput = (unsigned char *)malloc(len * sizeof(unsigned char));
    to_string(input, len, sinput);
    unsigned char * soutput = (unsigned char *)malloc((len * 2) * sizeof(unsigned char ));
    EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, skey, NULL);
    int ret = 0;
    int ret2 = 0;
    EVP_DecryptUpdate(ctx, soutput, &ret, sinput, len);
    EVP_DecryptFinal_ex(ctx, soutput + ret, &ret2);
    ret += ret2;
    soutput[ret] = '\0';
    from_string(soutput, output);
    EVP_CIPHER_CTX_free(ctx);
    free(skey); 
    free(sinput);
    free(soutput);
    return ret;
}

