from pwn import *

execve_file = './vuln'
libc_file = '/home/nemo/Pwn/glibc-all-in-one/libs/2.35-0ubuntu3.1_amd64/libc.so.6'

libc = ELF(libc_file)
libc.search()
for i in libc.sections:
    if i.name == "__libc_IO_vtables":
        mem = libc.mmap
        pos = i.header.sh_offset
        with mem:
            for offset in range(0, 0x100, 8):
                value1 = struct.unpack('Q', mem[pos+offset:pos+offset+8])[0]
                print(hex(pos+offset)+":"+hex(value1))
