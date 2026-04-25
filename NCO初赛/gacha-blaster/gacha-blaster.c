#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/*
gcc src/gacha-blaster.c -o src/gacha-blaster -O0 -fno-stack-protector -no-pie -U_FORTIFY_SOURCE
*/

static ssize_t load_flag(char *buffer, size_t size)
{
    int fd = open("flag.txt", O_RDONLY);
    if (fd < 0) {
        puts("[!] The prize vault is locked forever.");
        exit(1);
    }

    ssize_t bytes_read = read(fd, buffer, size - 1);
    close(fd);

    if (bytes_read <= 0) {
        puts("[!] The prize vault is empty.");
        exit(1);
    }

    buffer[bytes_read] = '\0';

    return bytes_read;
}

static void bonus_mode(void)
{
    char flag[64];
    static const char banner[] = "\n[+] Maintenance bonus mode unlocked!\nGolden capsule ticket: ";
    ssize_t flag_length;

    flag_length = load_flag(flag, sizeof(flag));
    write(STDOUT_FILENO, banner, sizeof(banner) - 1);
    write(STDOUT_FILENO, flag, (size_t)flag_length);
    write(STDOUT_FILENO, "\n", 1);
    _exit(0);
}

static void play_round(void)
{
    char battle_cry[32];

    puts("== Gacha Blaster 3000 ==");
    puts("Type a short battle cry to launch one capsule.");
    puts("Please keep it short so the machine does not jam.");
    printf("> ");

    read(STDIN_FILENO, battle_cry, 96);

    puts("\nThe machine shakes, flashes, and launches a capsule.");
    puts("A tiny sticker pops out: 'Better luck next time.'");
}

int main(void)
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    play_round();

    return 0;
}