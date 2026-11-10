#include <stdio.h>
#include <string.h>

void process_data(char *input) {
    char buffer[64];
    // Safe bounds-checked copy with guaranteed null-termination
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    printf("Processed: %s\n", buffer);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        process_data(argv[1]);
    }
    return 0;
}

