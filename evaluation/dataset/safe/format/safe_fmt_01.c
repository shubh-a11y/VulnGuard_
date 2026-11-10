#include <stdio.h>

void log_message(char *msg) {
    // Safe implementation: format specifier is a string literal
    printf("%s\n", msg);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        log_message(argv[1]);
    }
    return 0;
}

