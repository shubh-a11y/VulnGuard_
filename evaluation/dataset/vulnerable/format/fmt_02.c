#include <stdio.h>

void report_error(const char *err_msg) {
    // Format string vulnerability: err_msg supplied directly to fprintf without format specifier
    fprintf(stderr, err_msg);
    fprintf(stderr, "\n");
}

int main(int argc, char **argv) {
    if (argc > 1) {
        report_error(argv[1]);
    }
    return 0;
}

