# H@cktivityCon CTF 2020 `Statics and Dynamics` Writeup
Category Binary Exploitation  
Points: 200

## Description
```
A breakfast isn't complete without bacon
```
---

Where I run out of time, get the answer spoiled, and learn about ret2dlresolve

## Recon
We are given a single binary, `bacon`

```
> file bacon
bacon: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=dcf750042c29c6cc101017236958eb97f58483e8, for GNU/Linux 3.2.0, stripped

checksec --file=bacon
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   No Symbols        No    0               1               bacon
```

When run the binary seems to do nothing, taking a line of input and then exiting silently, never once printing to the screen.

A quick look in ghidra reveals this vulnerable function, which is a fairly obvious buffer overflow:

```c
void vulnerable(void)

{
  undefined buffer [1028];
  
  return_top_of_stack();
  read(0,buffer,0x42c);
  return;
}
```

`return_top_of_stack` sets EAX to the value pointed at by ESP. I'm not sure what it's purpose is, but it doesn't seem to affect the exploit at all, so I ignored it.

If you're up on your hex conversions, you might realize that 0x42c is larger than 1028 (0x404), meaning we have a 40 byte overflow. That's not a ton of space, but it turns out to be enough.

Unfortunately, this was as far as I was able to get before I had to start my actual job, and the CTF ended later that day, so I wasn't able to finish in time for points. Also unfortunately, I had the "answer" to the this challenge spoiled by accident for in the discord, so later that night after work I as able to get right to a working solution.

## ret2dlresolve
This binary is challenging because we don't have a way to get data back. It doesn't
write anything to the screen, so nothing like `write` or `puts` is available in the GOT. If we knew the address libc was loaded to we could call them directly, but in order to do that we would need to print it back to us, which leaves a catch 22.

The trick out of this is to hijack the linker's symbol resolution mechanism, and force it load a symbol we want. The binary needs to call this code in order to resolve imported symbols, and so it resides at a known offset. And since the binary isn't PIE, that means we know it's address and can ROP to it ourselves. Since this is the function used by the PLT/GOT to resolve symbols, it also automatically calls the resolved function, using the arguments passed on the stack. Quite convenient!

There's some work to do before we can directly call it, however. The resolver takes a pointer to an Elf32_Rel struct, which in turn needs to have a pointer to an Elf32_Sym struct. The Elf32_Sym struct needs to have a pointer to a string with the name of the symbol we would like to load (in this case, `system`). The Elf32_Rel struct also has to satisfy certain properties (flags being set, etc.)

```python
def build_elf32_sym():
    fake_sym = b""
    fake_sym += p32(SYSTEM_STR_ADDR - STRTAB) # st_name, points to "system"
    fake_sym += p32(0xAAAAAAAA) # st_value (unused)
    fake_sym += p32(0xBBBBBBBB) # st_size (unused)
    fake_sym += p32(0) # st_other; st_other & 3 must equal 0
    return fake_sym

def build_elf32_rel():
    fake_rel = b""
    fake_rel += p32(FAKE_REL_ADDR + 0x100) # r_offset; Arbitraty writeable address
    r_info = (FAKE_SYM_ADDR - SYMTAB) // 16
    r_info = (r_info << 8) | 7
    fake_rel += p32(r_info) # r_info; offset of fake sym struct, 7=R_386_JMP_SLOT
    return fake_rel
```

That's a fair bit to set up! In the exploit script I used multiple calls the `read` to write everything I needed into memory, but this could be done with one if you packed things correctly.

One final bit of trickiness is that the resolver doesn't actually take a direct pointer to the Elf32_Rel struct, it takes an offset from the `JUMPREL` section, the section of memory where the legitimate versions of these structs are stored.

## Flag
The full exploit script is available in `bacon.py`. I unfortunately was not able to solve this challenge during the contest, but the H@cktivity people kindly keep the challenges up for a couple of days after the contest, and I solved this one Friday night.

```
> cat flag.txt
flag{don't_forget_to_take_out_the_grease}
```

## P.S.
`pwntools` can actually do a lot of this for you. A script using the utilities provided by `pwntools` is available in `bacon_pwntools.py`.