#include <stdio.h>
#include <unistd.h>

void log_message(char *msg) {
    // VULNERABILITY: Format string vulnerability
    // The user controls the format string itself.
    // If msg is "%x %x %x", it will leak stack memory.
    // If msg is "%n", it can write to arbitrary memory locations.
    printf(msg);
    printf("\n");
}

int main(int argc, char **argv) {
    if (argc > 1) {
        log_message(argv[1]);
    }
    return 0;
}
