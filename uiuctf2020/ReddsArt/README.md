# UIUCTF 2020 login_page Writeup

Category: RE  
Points: 200

## [Description](https://ctftime.org/task/12408)
```
Redd has an enticing deal for you. Will you take it?

Author: 2much4u
```
---

We get a single file called `ReddsArt`. It's a stripped 64bit ELF.
```
> file ReddsArt
ReddsArt: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=c022d27a18dade5b1d3d52b1082c798548849c2b, stripped
```
Executing it makes us run through an agonizingly slow conversation tree, as it prints out each character one at a time. At the end, it spits out an obviously fake flag and exits.

Let's pop it open in [Ghidra](https://ghidra-sre.org/) and take a look. The binary is stripped so there's no obvious `main`, but it's easy enough to find by looking for `__libc_start_main`
```c
__libc_start_main(FUN_00100bea,in_stack_00000000,&stack0x00000008,FUN_00100ee0,FUN_00100f50,param_3,auStack8);
```
`FUN_00100bea` (or `main`) isn't very interesting. The options we have in the conversation flow are limited, and don't end up making any difference in the output. It only calls out to two other functions in the binary: 
- `FUN_00100b16`: Slowly prints out a passed string, character by character.
- `FUN_00100b82`: Prints out the fake flag.

There are some other functions in the binary however, ones that don't get called by default. One, `FUN_0010091a`, also refrences the fake flag:

```c
ulong FUN_0010091a(void)

{
  size_t sVar1;
  uint local_20;
  int local_1c;
  
  local_20 = 0;
  local_1c = 0;
  while( true ) {
    sVar1 = strlen(PTR_s_uiuctf{v3Ry_r341_@rTT}_00302010);
    if (sVar1 <= (ulong)(long)local_1c) break;
    local_20 = local_20 + (int)(char)PTR_s_uiuctf{v3Ry_r341_@rTT}_00302010[(long)local_1c];
    local_1c = local_1c + 1;
  }
  return (ulong)local_20;
}
```

Looks like it's summing up all the bytes in the fake flag and returning the result. Let's call this function `SumFakeFlag`, and go check out the one place it is called from
```c
void FUN_00100a5a(void)

{
  ulong uVar1;
  int local_18;
  
  uVar1 = SumFakeFlag();
  local_18 = 0;
  while (local_18 < 0xe7) {
    *(byte *)(FUN_00100973 + (long)local_18) = (byte)FUN_00100973[(long)local_18] ^ (byte)uVar1;
    local_18 = local_18 + 1;
  }
  return;
}
```
`FUN_00100a5a` is using the value returned by `SumFakeFlag` to decrypt the function at `FUN_00100973`. And sure enough, if we try to disassemble `FUN_00100973`, we can see that it's basically gibberish.

Thankfully, a quick python script is all that's need to do the decryption ourselves.
```python
target_function = "4b 56 97 ... (hex bytes of target function)"
key = 0xff & sum(ord(c) for c in "uiuctf{v3Ry_r341_@rTT}")
result_function = " ".join(hex(int(h, 16) ^ key)[2:].zfill(2) for h in target_function.split())
```
The result can be patched back in and disassembled/decompiled with Ghidra
```c
void FUN_00100973(void)

{
  char cVar1;
  size_t sVar2;
  ulong uVar3;
  int iStack44;
  int iStack40;
  
  cVar1 = *(char *)((long)DAT_00000009 + 9);
  iStack44 = 0;
  while( true ) {
    sVar2 = strlen(PTR_s_hthzgubI>*ww7>z+Ha,m>W,7z+hmG`_00302028);
    if (sVar2 <= (ulong)(long)iStack44) break;
    PTR_s_hthzgubI>*ww7>z+Ha,m>W,7z+hmG`_00302028[(long)iStack44] =
         PTR_s_hthzgubI>*ww7>z+Ha,m>W,7z+hmG`_00302028[(long)iStack44] + cVar1;
    iStack44 = iStack44 + 1;
  }
  uVar3 = SumFakeFlag();
  iStack40 = 0;
  while( true ) {
    sVar2 = strlen(PTR_s_hthzgubI>*ww7>z+Ha,m>W,7z+hmG`_00302028);
    if (sVar2 <= (ulong)(long)iStack40) break;
    PTR_s_hthzgubI>*ww7>z+Ha,m>W,7z+hmG`_00302028[(long)iStack40] =
         PTR_s_hthzgubI>*ww7>z+Ha,m>W,7z+hmG`_00302028[(long)iStack40] ^ (byte)uVar3;
    iStack40 = iStack40 + 1;
  }
  return;
}
```
Looks like it's taking a gibberish string, adding some constant to each character,and then XORing it with the value of `SumFakeFlag()` again. Another decryption. Unfortunately, it isn't as easy just forcing the binary to run this function, as the calculation to get the addition constant (`cVar1` in the above code) is borked. Here's the relevant assembly:
```
MOV        qword ptr [RBP + -0x18],0x9
MOV        RAX,qword ptr [RBP + -0x18]
MOVZX      EAX=>DAT_00000009,byte ptr [RAX]
```
It takes a couple of steps to do it, but this essentially ends up loading `0x9` into `RAX`, and then attempts to dereference it, which wil obviously fail. We don't know what the addition constant is supposed to be.

No worries, though! Since it's being added to a byte, there are only 256 possible values. We can loop through them all with another python script.
```python
key = 0xff & sum(ord(c) for c in "uiuctf{v3Ry_r341_@rTT}")
ciphertext = "hthzgubI>*ww7>z+Ha,m>W,7z+hmG`"

def decrypt(add_value):
    return ''.join(chr((ord(c) + add_value) ^ key) for c in ciphertext)

for i in range(0, 256):
    possible_flag = decrypt(i)
    if "uiuctf" in possible_flag:
        print(possible_flag)
        exit()
```
This prints out the real flag, which we can submit for points.
```
uiuctf{R_3dd$_c0Uz1n_D1$c0unT}
``` 
_Fin._