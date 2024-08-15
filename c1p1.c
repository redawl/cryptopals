#include <stdio.h>
#include <string.h>
#include "bytes.h"

int main(){
    char * hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";

    byte * data = alloc_bytes(strlen(hex));

    int len = from_hex(hex, data);
    print_b64(data, len);
    printf("\nSSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t\n");
    free(data);
}
