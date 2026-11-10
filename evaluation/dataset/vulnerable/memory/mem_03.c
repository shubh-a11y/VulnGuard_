#include <stdio.h>
#include <string.h>

void format_record(const char *id_str) {
    char rec[64];
    // Buffer overflow: sprintf writes unbounded user string into fixed buffer
    sprintf(rec, "ID:%s", id_str);
    printf("Record: %s\n", rec);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        format_record(argv[1]);
    }
    return 0;
}

