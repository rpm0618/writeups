# H@cktivityCon CTF 2020 `Almost` Writeup

Category Binary Exploitation  
Points: 100

## Description
```
Oh, just so close!
```
---

Where I learn about basic ROPing, leaking libc from the GOT, and [https://libc.blukat.me/](https://libc.blukat.me/)

## Recon
We are given a single binary, `almost`:

```
> file almost
almost: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=b441f1c371168594b8f562847c9fc92ab6327d36, not stripped

> checksec --file=almost
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   70) Symbols       No    0               2               almost
```

NX is enabled, so no easy shellcode, but no stack canaries and no PIE means we should be able to ROP around. It's not stripped, which is nice for gdb.

When run it claims to be a URL builder, and does deliver on the promise:

```
> ./almost
Welcome to the URL builder
Insert the protocol:
http
Insert the domain:
example.com
Insert the path:
test
Result:
http://example.com/test
Build another URL? [y/n]
n
Thanks for using our tool!
```

`main` is a wrapper that prints the welcome message and asks the user if they want to build another URL. It calls out to `build` to do the actual dirty work.

```c
void build(void)

{
  char cVar1;
  uint uVar2;
  char *pcVar3;
  byte bVar4;
  char protocol [64];
  char domain [64];
  char path [63]; // Should be 64, Ghidra is stupid
  char final_url [256];
  
  bVar4 = 0;

// The +1's on final_url are because of the incorrect buffer length above (or maybe the other way around)

  // Step 1
  memset(final_url + 1,0,0x100);
  puts("Insert the protocol:");
  getInput(protocol);
  puts("Insert the domain:");
  getInput(domain);
  puts("Insert the path:");
  getInput(path);

  // Step 2
  strcat(final_url + 1,protocol);
  
  /* Append "://" */
  uVar2 = 0xffffffff;
  pcVar3 = final_url + 1;
  do {
    if (uVar2 == 0) break;
    uVar2 = uVar2 - 1;
    cVar1 = *pcVar3;
    pcVar3 = pcVar3 + (uint)bVar4 * -2 + 1;
  } while (cVar1 != '\0'); // REPNE SCASB
  *(undefined4 *)(final_url + ~uVar2) = 0x2f2f3a;

  // Step 3
  strcat(final_url + 1,domain);

  /* Append "/" */
  uVar2 = 0xffffffff;
  pcVar3 = final_url + 1;
  do {
    if (uVar2 == 0) break;
    uVar2 = uVar2 - 1;
    cVar1 = *pcVar3;
    pcVar3 = pcVar3 + (uint)bVar4 * -2 + 1;
  } while (cVar1 != '\0'); // REPNE SCASB
  *(undefined2 *)(final_url + ~uVar2) = 0x2f;

  // Step 4
  strcat(final_url + 1,path);
  puts("Result:");
  puts(final_url + 1);
  return;
}
```

This function is fairly simple, even if Ghidra does manage to make a bit of a mess of the decompilation. I had to manually fix the size of the `final_url` buffer, and I couldn't figure out how to fix the length of the `path` buffer (and therefor `final_url`'s start location) without fucking everything up. Also, the nasty `do..while` loops are Ghidra's attempt to dissasemble the `REPNE SCASB` instruction, it's essentially just finding the end of the string so that the separators can be appended.

So with that in mind, here's what's happening:

1. Three strings are read in using `getInput`, which is supposed to limit itself to 64 characters. We'll get to that later.
2. The protocol is copied into the `final_url` buffer using `strcat`, and "://" is appended
3. The domain is appended to the end of `final_url` using `strcat`, and "/" is appended
4. Finally the path is appended to the end of `final_url` using `strcat`.

Naively, the most we can write into `final_url` is 196 bytes (`64 * 3 = 192` for the 3 url parts, and `4` more the separator characters). That's not enough to overflow the 256 bytes of `final_url`, so we'll have to look elsewhere.

## Buffer Overflow

A cursory look at `getInput` shows that it tries to limit the number of characters it writes to 64, but a closer look shows that there is an off by one error, and it can potentially write out up to 65 characters (64 from the input plus a trailing null byte)

```c
void getInput(char *buffer)

{
  char character;
  int iVar1;
  int temp;
  int count;
  
  count = 0;
  while (count < 0x40 /* 64 */) {
    iVar1 = getchar();
    character = (char)iVar1;
    if ((character == '\n') || (character == -1)) break;
    buffer[count] = character;
    count = count + 1;
  }
  // if count == 64 here, then buffer[count] actually writes to the 65th byte!
  buffer[count] = '\0';

  // Clear out rest of line, if 64 or more characters entered
  if (0x3f < count) {
    do {
      temp = getchar();
      if ((char)temp == '\n') {
        return;
      }
    } while ((char)temp != -1);
  }
  return;
}
```

We can use this off by one to make the different url parts to be longer than 64 bytes, by overwriting their terminating null:

```
Before protocol read (garbage on stack)
+-----------------------+------------------
|protocol buffer        |domain buffer
+-----------------------+------------------
|xx|xx|xx|xx|xx|xx|xx|xx|xx|xx|xx|xx|xx|...
+-----------------------+------------------

Read 64 bytes for protocol (null terminator overflows)
+-----------------------+------------------
|protocol buffer        |domain buffer
+-----------------------+------------------
|41|41|41|41|41|41|41|41|00|xx|xx|xx|xx|...
+-----------------------+------------------

Read 64 bytes for domain (null terminator is overwritten)
+-----------------------+------------------
|protocol buffer        |domain buffer
+-----------------------+------------------
|41|41|41|41|41|41|41|41|42|42|42|42|42|...
+-----------------------+------------------
```

This will cause `strcat` to copy more than the 64 bytes it's expected to into `final_url`, and in fact enough can be written to overflow the return pointer on the stack.

I wrote 64 bytes for both the `protocol` and `domain` buffers, and the final payload went into the `path` buffer. The exact offset is a little tricky to figure out, since it depends on the size of your payload. Instead of doing the math, I just fiddled around until I found a good length of padding, and just overwrote bytes in that to keep the length the same. Thankfully I didn't end up needing any more, or I would have had to repeat the process with a longer padding string.

## Libc Leak

I had been pretty comfortable with everything up to this point, but I hit a roadblock here. The binary doesn't support ASLR, but libc is dynamically loaded and it's address will be randomized, so in order to perform a ret2libc we'll need to somehow leak the offset of libc in memory (we'll also need to know what version of libc we have, because that will change the location of functions).

After some googling, I found [this](https://book.hacktricks.xyz/exploiting/linux-exploiting-basic-esp/rop-leaking-libc-address) writeup, which solves both of those problems. It shows how to leak the address of libc functions by reading out their address from the Global Offset Table (GOT), which is a static location where they dynamic linker store information about external functions. It then shows how to use those leaked offsets to find possible libc versions using [https://libc.blukat.me/](https://libc.blukat.me/).

So the exploit is as follows:

1. Determine libc version
    1. Leak some addresses out of the GOT (at least one, preferably multiple)
    2. Put those address into [https://libc.blukat.me/](https://libc.blukat.me/), and grab the useful offsets for the libc it spits out (or just download the entire `.so` for use in pwntools)
2. Pop shell
    1. Leak address of `puts` (or some other function) and subtract the base offset of the function in libc. This gives the ASLR offset of the entire libc library
    2. Construct a standard ret2libc payload, calling `system` with `"/bin/sh"`

Let's look at the payload for leaking the GOT address

```python
def get_got_address(stream, got):
    payload = b""
    payload += p32(e.plt["puts"]) # Call puts
    payload += p32(POP_RET) # Fix stack
    payload += p32(e.got[got]) # argument to puts
    payload += p32(e.symbols["build"]) # When done, return to build
    trigger_overflow(stream, payload)
    leaked_address = u32(stream.recvline()[:4]) # We only care about the first 4 bytes
    return leaked_address
```

We overwrite the return pointer with the address of `puts` in the PLT, which is a static location. We pass the address of the GOT symbol we want to look up as an argument. That will cause puts to output the address of the libc `puts` to STDOUT (along with some other garbage probably, but we don't care about that). After `puts` completes, it returns into a `pop; ret;` to pop the argument to `puts` of the stack and return back into the build function, so we can repeat the exploit.

## Flag

The full exploit script is available in `almost.py`. When run it will pop a shell and hand over control, letting us cat flags to our hearts content

```
> cat flat.txt
flag{my_code_was_almost_secure}
```

_Fin._