#include <stdio.h>
#include <string.h>

void process_data(char *input) {
    char buffer[64];
    
    // VULNERABILITY: Classic buffer overflow. strcpy does not check bounds.
    // If input is > 64 bytes, it will overwrite the return address on the stack.
    strcpy(buffer, input);
    
    printf("Processed: %s\n", buffer);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        process_data(argv[1]);
    }
    return 0;
}
