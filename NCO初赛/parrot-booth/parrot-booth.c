#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
gcc src/parrot-booth.c -o src/parrot-booth -O0 -fno-stack-protector -no-pie -U_FORTIFY_SOURCE
*/

typedef struct {
    char line[10];
    char flag[64];
} parrot_memory_t;

static void load_flag(char *buffer, size_t size)
{
    int fd = open("flag.txt", O_RDONLY);
    if (fd < 0) {
        puts("[!] The parrot lost its secret note.");
        exit(1);
    }

    ssize_t bytes_read = read(fd, buffer, size - 1);
    close(fd);

    if (bytes_read <= 0) {
        puts("[!] The secret note is blank.");
        exit(1);
    }

    buffer[bytes_read] = '\0';
}

static void read_line(char *buffer, size_t size)
{
    size_t index = 0;

    while (index < size) {
        ssize_t bytes_read = read(STDIN_FILENO, &buffer[index], 1);
        if (bytes_read <= 0) {
            break;
        }

        if (buffer[index] == '\r') {
            continue;
        }

        if (buffer[index] == '\n') {
            break;
        }

        index++;
    }
}

int main(void)
{
    parrot_memory_t memory;

    memset(&memory, 0, sizeof(memory));
    load_flag(memory.flag, sizeof(memory.flag));

    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    puts("== Parrot Booth ==");
    puts("The robot parrot can repeat one short line.");
    puts("Keep it neat: 10 characters is usually plenty.");
    printf("> ");

    read_line(memory.line, sizeof(memory.line));

    printf("\nParrot: %s\n", memory.line);
    puts("Thanks for visiting the booth.");

    return 0;
}