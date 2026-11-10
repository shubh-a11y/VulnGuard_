#include <stdio.h>

void report_error(const char *err_msg) {
    // Safe implementation: format specifier is a string literal
    fprintf(stderr, "%s\n", err_msg);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        report_error(argv[1]);
    }
    return 0;
}

