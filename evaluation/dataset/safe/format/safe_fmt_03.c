#include <stdio.h>

void format_status(char *out, size_t out_sz, const char *status_msg) {
    // Safe implementation: format specifier is a string literal
    snprintf(out, out_sz, "%s", status_msg);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        char buf[128];
        format_status(buf, sizeof(buf), argv[1]);
        printf("%s\n", buf);
    }
    return 0;
}

