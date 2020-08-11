# H@cktivity Con 2020 `Space Force` writeup
Category: Binary Exploitation  
Points: 350

## Description
```
I wanna go to space!!!

Note: Be sure to use the provided libc
```
---

Where I learn to trust in malloc and use the Force

## Recon
We are given a binary, `space`, and `libc-2.27.so`, which is an old version of libc. This was suspicious.

```
> file space
space: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter ./ld-2.27.so, BuildID[sha1]=de68fbc91d84b63ff2947193de45e13f7fae0e16, for GNU/Linux 3.2.0, not stripped

> checksec --file=space
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   91) Symbols       No    0               3               space
```

And this confirmed it for me. Pretty much full protections across the board, this was probably a heap challenge. Which meant I was doomed. I had never done a heap challenge before, and between work and needing to sleep for work, I knew I wouldn't have enough time during the CTF to learn. Thankfully after the CTF was the weekend, where I had plenty of time to learn.

I stumbled upon the video [Introduction To GLIBC Heap Exploitation - Max Kamper](https://www.youtube.com/watch?v=6-Et7M7qJJg), which is an excellent start. The audio is a little choppy in the beginning, push through. So worth it in fact that I ended up purchasing Max's [Udemy course](https://www.udemy.com/course/linux-heap-exploitation-part-1/), which I highly recommend if you have the money (try signing up with a new email address, it gave me a ~80% discount).

After spending the weekend completing the course and it's challenges (looking forward to part 2!), I was ready to run give `space` a shot.


## Libc shenanigans
The first challenge was getting the binary to actually run using the provided libc. A compatible version of ld.so wasn't provided, but thankfully the Udemy course mentioned above came with a couple of versions of libc and ld (with debug symbols), so I was able to pull a matching version from there.

Once I had that, I was able to use `patchelf` with the `--set-interpreter` command to force the binary to use the right dynamic linker, and set the `LD_LIBRARY_PATH` environment variable to a folder including a version of libc 2.27.