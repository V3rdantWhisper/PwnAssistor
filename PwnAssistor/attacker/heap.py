from pwn import tubes, log, u64


def recv_bytes_addr(p, offset: int, terminator: bytes, leak_type: str):
    leak = u64(p.recvuntil(terminator)[-6:]+b'\x00\x00') - offset
    log.success(f'{leak_type} leak: {str(leak)}')
    return leak


def recv_heap_addr(p, offset: int, terminator: bytes = b'\x55'):
    return recv_bytes_addr(p, offset, terminator, leak_type='heap')


def recv_libc_addr(p, offset: int, terminator: bytes = b'\x7f'):
    return recv_bytes_addr(p, offset, terminator, leak_type='libc')

