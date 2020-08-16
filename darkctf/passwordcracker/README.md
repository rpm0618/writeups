# Dark CTF `PasswordCracker` Writeup

This was a bit of a strange one, and I'm curious as to what the intended solution is. The binary itself does some input validation, checks more input against a random number, and assuming all of those work starts generating large primes? (Not sure about the last part, didn't bother verifying)

That's irrelevant though, because there's also a function `dwp_ymrakrad` which prints the flag:

```c
void dwp_ymrakrad(void)

{
  undefined8 local_28;
  undefined8 local_20;
  undefined4 local_18;
  undefined2 local_14;
  int local_c;
  
  local_28 = 0x7b4654436b726164;
  local_20 = 0x5f6e695f67616c66;
  local_18 = 0x63617473;
  local_14 = 0x7d6b;
  local_c = 0;
  while (local_c < 0x16) {
    putchar((uint)*(byte *)((long)&local_28 + (long)local_c));
    local_c = local_c + 1;
  }
  putchar(10);
  return;
}
```

Those pushed values can be decded into ASCII and assembled, revealing the flag:

```
darkCTF{flag_in_stack}
```

As I said, I'm curious as to the intended solution. This was labeled as a pwn challenge and there is a buffer overflow when reading in the name (with stack canaries turned off), but because there's no server and the flag is hardcoded,
it's never relevant.