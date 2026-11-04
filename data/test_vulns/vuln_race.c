#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

void write_secure_log(const char *filename, const char *msg) {
    // VULNERABILITY: TOCTOU (Time of Check to Time of Use) Race Condition
    // 
    // Step 1: Check if the user has access to write to the file
    if (access(filename, W_OK) != 0) {
        printf("Access denied to %s\n", filename);
        return;
    }
    
    // --> WINDOW OF VULNERABILITY <--
    // An attacker can swap `filename` from a legitimate file to a symlink
    // pointing to /etc/shadow during this brief window.
    
    // Step 2: Open and write to the file (assuming the check above is still valid)
    int fd = open(filename, O_WRONLY | O_APPEND);
    if (fd == -1) {
        perror("open");
        return;
    }
    
    write(fd, msg, strlen(msg));
    close(fd);
    printf("Log written securely.\n");
}

int main(int argc, char **argv) {
    if (argc > 2) {
        write_secure_log(argv[1], argv[2]);
    } else {
        printf("Usage: %s <file> <message>\n", argv[0]);
    }
    return 0;
}
