#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char ** argv){
    float * vals = (float *)malloc(255 * sizeof(float));
    for(int i = 0; i < 255; i++){
        vals[i] = 0;
    }
    
    for(int i = 0; i < strlen(argv[1]); i++){
        vals[argv[1][i]]++;
    }

    printf("[%d] = {", 255);
    for(int i = 0; i < 255; i++){
        printf("%f, ", vals[i] / strlen(argv[1]));
    }
    printf("};\n");
}
