#include <stdio.h>
#include <string.h>

void concat_headers(const char *user_val) {
    char out[64] = "Header: ";
    // Buffer overflow: strcat appends without verifying remaining capacity
    strcat(out, user_val);
    printf("Result: %s\n", out);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        concat_headers(argv[1]);
    }
    return 0;
}

