#Made by fly_autumn
#testnc......
from pwn import *
p = process("./shell_asm")
elf = ELF("./shell_asm")
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
context(os="linux",arch="amd64")



p.interactive()
