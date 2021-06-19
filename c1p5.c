#include <stdio.h>
#include <string.h>
#include "bytes.h"

int main(){
    char * data = "Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal";
    struct byte * bytes = alloc_bytes(strlen(data));
    int len = from_string(data, bytes);
    struct byte * output = alloc_bytes(len);
    char * keydata = "ICE";
    struct byte * key = alloc_bytes(3);
    int keylen = from_string(keydata, key);
    repeating_key_xor(bytes, key, len, keylen, output);
    print_hex(output, len);
    printf("\n0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f\n");
    free(bytes);
    free(output);
    free(key);
}
