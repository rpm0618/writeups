# H@cktivityCon CTF 2020 `Statics and Dynamics` Writeup
Category Binary Exploitation  
Points: 100

## Description
```
Everybody likes the dynamic side of things, what about the static?
```
---

Where I bypass the intended solution and learn about defeating DEP/NX with `mprotect`

## Recon
We are given a single binary, `sad`:

```
> file sad
sad: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=603eb2dd7bf8d6f483505b9e686b9163e6f69d14, for GNU/Linux 3.2.0, not stripped

> checksec --file=sad
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   1901) Symbols     No    0               0               sad
```

Like the description hints at, this is a statically compiled binary. `checksec` finding stack canaries scared me a little, but I think it's just picking them up from the compiled in libc.

A quick look in ghidra reveals that while a whole lot is compiled in to this binary, it doesn't actually do much:

```c
undefined8 main(void)
{
  char buffer [256];
  
  setup();
  puts("This is a really big binary. Hope you have everything you need ;)");
  gets(buffer);
  return 0;
}
```

A fairly obvious buffer overflow. It would be a standard ret2libc, but of course everything's been compiled directly in, and all of the good stuff (`system`, `execve`, etc.) has been left out. One way of dealing with this (and I think the intended one) is to make the right syscall yourself (That's how the above functions work, they end up triggering a syscall and telling the kernel to do things). In order to make that work you need to be able to control a number of registers, but since a good portion of libc has been linked directly into the binary you have plenty of gadgets to work with.

However as I was trawling through ghidra's function list looking for `main`, I noticed that `mprotect` had also been included. The binary has been setup for NX, disallowing execution for data sections of memory, but `mprotect` lets a user permission sections of memory however they want. This can potentially be used to grant yourself a region of writeable and executable memory, allowing a more old school return into shellcode. I had never done this before, so I decided to give it a shot.

## `mprotect`

The setup here is pretty straightforward:

1. Return to `gets` (or `read`) to write some shellcode to an area of memory we know the address of (I used the `.bss` section)
2. Return into the mprotect function, causing it to mark that area of memory as executable
3. Finally return to the shellcode you just wrote.

`pwntools` makes this dead easy:

```python
e = ELF("./sad")
rop = ROP(e)

BSS = e.bss()

rop.gets(BSS) # Write shellcode to memory
rop.mprotect(BSS, 0x100, 0x1 | 0x2 | 0x4) # Make memory executable
rop.raw(BSS) # Jump to the shellcode

payload = rop.chain()
```

Trying to run this however will segfault. Inspecting in gdb reveals that we tried to jump to the correct address, but we segfaulted anyway. Looks like the mprotect call didn't work.

## Pages

A more careful reading of the `mprotect` man page reveals the issue. The address you pass to it must be page aligned. It turns out that these permissions are enforced on the page level, not on the byte level. `pwntools` probably has some utility to align address to a page (it has everything else), but I don't know what it is, so I just hardcoded the offset.

After that it worked like a charm.

## Flag

The full exploit script is available in `sad.py`.

```
> cat flag.txt
flag{radically_statically_roppingly_vulnerable}
```

_Fin._