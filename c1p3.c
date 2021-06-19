#include <stdio.h>
#include <string.h>
#include "bytes.h"

int main(){
    char * data = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    struct byte * bytes = alloc_bytes(strlen(data));
    int len = from_hex(data, bytes);
    struct byte * output = alloc_bytes(len);
    single_byte_xor_decrypt(bytes, len, output);
    print(output, len);
    printf("\n");
    free(output);
    free(bytes);   
}
