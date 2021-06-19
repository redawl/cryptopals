#include <stdio.h>
#include <string.h>
#include "bytes.h"

void print_bytes (const struct byte * bytes, int len) {
    for (int i = 0; i < len; i++) {
        struct byte temp;
        temp.data = bytes[i].data;
        for (int j = 1; j <= MAX_BYTE; j *= 2) {
            if (temp.data - MAX_BYTE / j >= 0) {
                printf("1");
                temp.data -= MAX_BYTE / j;
            } else {
                printf("0");
            }
        }
        printf(" ");
    }
}

void print_hex_helper (struct byte b) {
    if(b.data >= 0 && b.data <= 9) printf("%c", b.data + '0');
    else if(b.data >= 10 && b.data <= 15) printf("%c", b.data + 'a' - 10);
    else printf("?"); // prints if invalid hex        
}

void print_hex (const struct byte * hex, int len) {
    for (int i = 0; i < len; i++) {
        struct byte temp1;
        temp1.data = hex[i].data << 4;
        temp1.data = temp1.data >> 4;
        struct byte temp2;
        temp2.data = hex[i].data >> 4;
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
    else return '?'; //if invalid b64
}

void print_b64 (const struct byte * b64, int len) {
    for (int i = 0; i < len - (len % 3); i += 3) {
        struct byte temp1;
        temp1.data = b64[i].data >> 2;
        struct byte temp2;
        temp2.data = b64[i].data << 6;
        temp2.data = temp2.data >> 2;
        temp2.data += b64[i + 1].data >> 4;
        struct byte temp3;
        temp3.data = b64[i + 1].data << 4;
        temp3.data = temp3.data >> 2;
        temp3.data += b64[i + 2].data >> 6;
        struct byte temp4;
        temp4.data = b64[i + 2].data << 2;
        temp4.data = temp4.data >> 2;
        printf("%c%c%c%c", print_b64_helper(temp1.data), print_b64_helper(temp2.data), 
               print_b64_helper(temp3.data), print_b64_helper(temp4.data));
    }
    if (len % 3 == 1) {
        struct byte temp1;
        temp1.data = b64[len - 1].data >> 2;
        struct byte temp2;
        temp2.data = b64[len - 1].data << 6;
        temp2.data = temp2.data >> 2;
        printf("%c%c%c%c", print_b64_helper(temp1.data),
               print_b64_helper(temp2.data), '=', '=');
    } else if(len % 3 == 2) {
        struct byte temp1;
        temp1.data = b64[len - 2].data >> 2;
        struct byte temp2;
        temp2.data = b64[len - 2].data << 6;
        temp2.data = temp2.data >> 2;
        temp2.data += b64[len - 1].data >> 4;
        struct byte temp3;
        temp3.data = b64[len - 1].data << 4;
        temp3.data = temp3.data >> 2;
        printf("%c%c%c%c", print_b64_helper(temp1.data),
               print_b64_helper(temp2.data), print_b64_helper(temp3.data), '=');
    }
}

struct byte * alloc_bytes (int len) {
    return (struct byte *)malloc(len * sizeof(struct byte));
}

void print (const struct byte * string, int len) {
    for (int i = 0; i < len; i++) {
        printf("%c", string[i].data);
    }
}   

int cat (struct byte * d1, int l1, struct byte * d2, int l2, struct byte * output) {
    memcpy(output, d1, l1);
    memcpy(output + l1, d2, l2);
    return l1 + l2;
}
unsigned char from_hex_helper (unsigned char hex) {
    if (hex >= 'a' && hex <= 'f') return hex - 'a' + 10;
    else if (hex >= '0' && hex <= '9') return hex - '0';
    else return '?'; //if invalid hex
}
int from_hex (char * hex, struct byte * bytes) {
    int counter = 0;
    for (int i = 0; i < strlen(hex); i += 2) {
        struct byte temp;
        temp.data = from_hex_helper(hex[i]) << 4;
        temp.data += from_hex_helper(hex[i+1]);
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
    else return '?'; //invalid b64 
}

int from_b64 (char * b64, struct byte * bytes) {
    int len = strlen(b64);
    int counter = 0;
    if(b64[len - 1] == '=') len -= 4;
    for (int i = 0;  i < len; i += 4) {
        struct byte temp1;
        temp1.data = from_b64_helper(b64[i]) << 2;
        temp1.data += from_b64_helper(b64[i+1]) >> 4;
        struct byte temp2;
        temp2.data = from_b64_helper(b64[i+1]) << 4;
        temp2.data += from_b64_helper(b64[i+2]) >> 2;
        struct byte temp3;
        temp3.data = from_b64_helper(b64[i+2]) << 6;
        temp3.data += from_b64_helper(b64[i+3]);
        bytes[counter] = temp1;
        counter++;
        bytes[counter] = temp2;
        counter++;
        bytes[counter] = temp3;
        counter++;
    }

    len = strlen(b64);
    if (b64[len - 1] == '=' && b64[len - 2] == '=') {
        struct byte temp1;
        temp1.data = from_b64_helper(b64[len - 4]) << 2;
        temp1.data += from_b64_helper(b64[len - 3]) >> 4;
        bytes[counter] = temp1;
        counter++;
    } else if (b64[len - 1] == '=') {
        struct byte temp1;
        temp1.data = from_b64_helper(b64[len - 4]) << 2;
        temp1.data += from_b64_helper(b64[len - 3]) >> 4;
        struct byte temp2;
        temp2.data = from_b64_helper(b64[len - 3]) << 4;
        temp2.data += from_b64_helper(b64[len - 2]) >> 2;
        bytes[counter] = temp1;
        counter++;
        bytes[counter] = temp2;
        counter++;
    }


    return counter;
}

int from_string (char * str, struct byte * bytes) {
    for (int i = 0; i < strlen(str); i++) {
        bytes[i].data = str[i];
    }

    return strlen(str);
}

void to_string (struct byte * bytes, int len, unsigned char * str) {
    for (int i = 0; i < len; i++) {
        str[i] = bytes[i].data;
    }
}

void XOR (struct byte * b1, struct byte * b2, struct byte * output, int len) {
    for (int i = 0; i < len; i++) {
        output[i].data = b1[i].data ^ b2[i].data;
    }
}

float english_score (struct byte * b, int len) {
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
        ret += scores[b[i].data];
    }
    return ret;
}

void single_byte_xor (struct byte * b, int len, struct byte key, struct byte * output) {
    for (int i = 0; i < len; i++) {
        output[i].data = b[i].data ^ key.data;
    }
}

unsigned char single_byte_xor_decrypt (struct byte * b, int len, struct byte * output) {
    float max = 0.0;
    struct byte * temp = alloc_bytes(len);
    unsigned char ret;
    for (unsigned char i = 0; i < MAX_BYTE; i++) {
        struct byte key;
        key.data = i;
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

void repeating_key_xor (struct byte * b, struct byte * key, int len, int keylen, struct byte * output) {
    for(int i = 0; i < len; i++){
        output[i].data = b[i].data ^ key[i % keylen].data;
    }
}

int hamming (struct byte * b1, struct byte * b2, int len) {
    int ret = 0;
    for (int i = 0; i < len; i++) {
        struct byte temp;
        temp.data = b1[i].data ^ b2[i].data;
        for (int j = 1; j <= MAX_BYTE; j *= 2) {
            if (temp.data - MAX_BYTE / j >= 0) {
                ret++;
                temp.data -= MAX_BYTE / j;
            }
        }
    }
    return ret;
}

void repeating_key_xor_decrypt (struct byte * b, int len, struct byte * output) {
    struct byte * temp1 = alloc_bytes(len);
    struct byte * temp2 = alloc_bytes(len);
    struct byte * temp3 = alloc_bytes(len);
    struct byte * temp4 = alloc_bytes(len);
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
        struct byte * key = alloc_bytes(keysize[k]);
        struct byte * trash = alloc_bytes(len);
        struct byte * trash2 = alloc_bytes(len);
        for (int i = 0; i < keysize[k]; i++) {
            int counter = 0;
            for (int j = i; j < len; j += keysize[k]) {
                trash[counter] = b[j];
                counter++;
            }
            key[i].data = single_byte_xor_decrypt(trash, counter, trash2);
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

int aes_128_ecb_decrypt (struct byte * input, int len, struct byte * key, int keylen, struct byte * output) {
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
