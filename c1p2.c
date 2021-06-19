#include <stdio.h>
#include <string.h>
#include "bytes.h"

int main(){
    char * hex1 = "1c0111001f010100061a024b53535009181c";
    char * hex2 = "686974207468652062756c6c277320657965";
    struct byte * bytes1 = alloc_bytes(strlen(hex1));
    struct byte * bytes2 = alloc_bytes(strlen(hex2));

    int len = from_hex(hex1, bytes1);
    from_hex(hex2, bytes2);
    
    struct byte * output = alloc_bytes(len);
    XOR(bytes1, bytes2, output, len);
    print_hex(output, len);
    printf(" = 746865206b696420646f6e277420706c6179\n");
    free(bytes1);
    free(bytes2);
    free(output);
}
