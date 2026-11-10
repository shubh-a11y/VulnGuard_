#include <stdio.h>
#include <string.h>

void concat_headers(const char *user_val) {
    char out[64] = "Header: ";
    size_t current_len = strlen(out);
    if (current_len < sizeof(out) - 1) {
        // Safe concatenation bounded by remaining buffer space
        strncat(out, user_val, sizeof(out) - current_len - 1);
    }
    printf("Result: %s\n", out);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        concat_headers(argv[1]);
    }
    return 0;
}

