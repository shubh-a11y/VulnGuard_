#include <stdio.h>
#include <string.h>

void process_data(char *input) {
    char buffer[64];
    // Buffer overflow: unbounded strcpy into 64-byte stack buffer
    strcpy(buffer, input);
    printf("Processed: %s\n", buffer);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        process_data(argv[1]);
    }
    return 0;
}

