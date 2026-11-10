#include <stdio.h>
#include <string.h>

int load_profile(const char *base_dir, const char *filename, char *output, size_t max_len) {
    // Safe implementation: reject directory separators and relative traversal sequences
    if (strchr(filename, '/') != NULL || strchr(filename, '\\') != NULL || strstr(filename, "..") != NULL) {
        return -2;
    }
    char full_path[512];
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
    int rc = load_profile(argv[1], argv[2], buf, sizeof(buf));
    if (rc == 0) {
        printf("%s\n", buf);
        return 0;
    }
    return 2;
}

