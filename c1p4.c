#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bytes.h"

int main(){
    int counter = 0;
    char * data = (char *)malloc(100 * sizeof(char));
    float max = 0.0;
    struct byte * ans = alloc_bytes(100);
    struct byte * bytes = alloc_bytes(100);
    struct byte * bytes2 = alloc_bytes(100);

    int len = 0;
    for (int i = 0; i < 327; i++) {
        scanf("%s", data);
        len = from_hex(data, bytes);
        single_byte_xor_decrypt(bytes, len, bytes2);
        float temp = english_score(bytes2, len);
        if (temp > max) {
            max = temp;
            memcpy(ans, bytes2, len);
        }
    }
    free(data);
    free(bytes);
    free(bytes2);
    print(ans, len);
    printf("\n");
    free(ans);
}
