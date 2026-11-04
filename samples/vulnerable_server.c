#include <stdio.h>
#include <string.h>

void process_request(char *user_input) {
    char buffer[64];
    
    // VULNERABILITY: strcpy does not check bounds. 
    // If user_input is > 64 bytes, it will overflow the buffer.
    strcpy(buffer, user_input);
    
    printf("Request processed: %s\n", buffer);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        process_request(argv[1]);
    }
    return 0;
}
