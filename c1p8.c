#include "lib/bytes/bytes.h"

int main (int argc, char ** argv) {
    byte * data = from_file("data/c1p8.txt");

    int len = strlen(data);
    int num_lines = num_splits(data, '\n');
    byte ** lines = split(data, '\n', num_lines);

    int min_index = 0;
    int min = 100;

    for (int i = 0; i < num_lines; i++) {
        int e = entropy(lines[i], 32);

        if (e < min) {
            min = e;
            min_index = i;
        }
    }

    printf("'%s' (entropy %d) was most likely encrypted with AES in ECB\n", lines[min_index], min);

    free(data);
    for (int i = 0; i < num_lines; i++){
        free(lines[i]);
    }
    free(lines);

    return 0;
}
