#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
gcc src/slime-lab.c -o src/slime-lab -O0 -fno-stack-protector -no-pie -U_FORTIFY_SOURCE
*/

#define GOLDEN_CODE 0x52415453u

typedef struct {
    char codename[24];
    char slogan[16];
    unsigned int stickers;
    unsigned int judge_code;
} slime_profile_t;

static slime_profile_t profile;

static ssize_t read_line(char *buffer, size_t size)
{
    size_t index = 0;

    while (index + 1 < size) {
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

    buffer[index] = '\0';
    return (ssize_t)index;
}

static void load_flag(char *buffer, size_t size)
{
    int fd = open("flag.txt", O_RDONLY);
    if (fd < 0) {
        puts("[!] The golden recipe notebook is missing.");
        exit(1);
    }

    ssize_t bytes_read = read(fd, buffer, size - 1);
    close(fd);

    if (bytes_read <= 0) {
        puts("[!] The golden recipe notebook is blank.");
        exit(1);
    }

    buffer[bytes_read] = '\0';
}

static void init_profile(void)
{
    memset(&profile, 0, sizeof(profile));
    strcpy(profile.codename, "Bloby");
    strcpy(profile.slogan, "Go slime!");
    profile.stickers = 3;
}

static void show_profile(void)
{
    puts("\n== Slime Profile ==");
    printf("Codename : %s\n", profile.codename);
    printf("Slogan   : %s\n", profile.slogan);
    printf("Stickers : %u\n", profile.stickers);
}

static void rename_slime(void)
{
    puts("\nGive your slime a dramatic codename.");
    puts("The teacher says long names look cooler on the big screen.");
    printf("> ");

    read_line(profile.codename, 64);

    puts("The machine updates your slime badge.");
}

static void collect_sticker(void)
{
    if (profile.stickers >= 9) {
        puts("\nThe sticker tray is full already.");
        return;
    }

    profile.stickers++;
    puts("\nYou got another sparkly slime sticker.");
}

static void golden_recipe(void)
{
    char flag[64];

    puts("\nChecking judge-only access...");

    if (profile.judge_code != GOLDEN_CODE) {
        puts("Only official judges can open the golden slime vault.");
        return;
    }

    if (profile.stickers >= 3) {
        puts("Oops, you dropped some stickers while trying to open the vault. The slime machine is not happy.");
        return;
    }

    load_flag(flag, sizeof(flag));
    printf("Golden slime recipe: %s\n", flag);
}

static void menu(void)
{
    char choice[8];

    while (1) {
        puts("\n== Slime Lab 9000 ==");
        puts("1. Show slime profile");
        puts("2. Rename slime");
        puts("3. Collect sticker");
        puts("4. Open golden recipe vault");
        puts("5. Exit");
        printf("> ");

        read_line(choice, sizeof(choice));

        switch (choice[0]) {
        case '1':
            show_profile();
            break;
        case '2':
            rename_slime();
            break;
        case '3':
            collect_sticker();
            break;
        case '4':
            golden_recipe();
            break;
        case '5':
            puts("\nThe lab lights power down for the day.");
            return;
        default:
            puts("\nThe slime machine wiggles in confusion.");
            break;
        }
    }
}

int main(void)
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    init_profile();
    menu();

    return 0;
}