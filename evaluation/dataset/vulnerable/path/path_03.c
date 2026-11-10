#include <stdio.h>
#include <string.h>

int load_profile(const char *base_dir, const char *filename, char *output, size_t max_len) {
    char full_path[512];
    // Path traversal vulnerability: formatting user input directly into path
    snprintf(full_path, sizeof(full_path), "%s/%s", base_dir, filename);
    FILE *fp = fopen(full_path, "r");
    if (!fp) {
        return -1;
    }
    size_t n = fread(output, 1, max_len - 1, fp);
    output[n] = '\0';
    fclose(fp);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        return 1;
    }
    char buf[1024];
    if (load_profile(argv[1], argv[2], buf, sizeof(buf)) == 0) {
        printf("%s\n", buf);
        return 0;
    }
    return 2;
}

