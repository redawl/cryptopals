#include <stdio.h>
#include <string.h>
#include "lib/bytes/bytes.h"

int main(){
    byte * hex = from_file("data/c1p1.txt");


    int hexLen = strlen(hex);

    byte * data = alloc_bytes(hexLen);

    int len = from_hex(hex, data);
    print_b64(data, len);
    printf("\nSSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t\n");
    free(data);
    free(hex);
}
