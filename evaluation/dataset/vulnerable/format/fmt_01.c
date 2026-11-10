#include <stdio.h>

void log_message(char *msg) {
    // Format string vulnerability: user input directly used as format specifier
    printf(msg);
    printf("\n");
}

int main(int argc, char **argv) {
    if (argc > 1) {
        log_message(argv[1]);
    }
    return 0;
}

