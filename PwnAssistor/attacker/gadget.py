import subprocess


class Gadget:
    def __init__(self, libc_path: str):
        self.libc_path = libc_path

    def __get_gadget_by_opcode(self, opcode: str):
        out_ = subprocess.check_output(["ROPgadget", "--binary", self.libc_path, "--opcode", opcode]) \
            .decode('utf-8', errors='ignore').splitlines()[2:][0]

        if out_ is None:
            raise Exception("No gadget found")

        gadget_addr = int(out_.split(":")[0], 16)

        return gadget_addr

    def get_magic_gadget(self):
        return self.__get_gadget_by_opcode("488b570848890424ff5220")

    def get_pop_rdi(self):
        return self.__get_gadget_by_opcode("5fc3")

    def get_pop_rsi(self):
        return self.__get_gadget_by_opcode("5ec3")

    def get_pop_rax(self):
        return self.__get_gadget_by_opcode("58c3")

    def get_ret(self):
        return self.__get_gadget_by_opcode("c3")

    def get_pop_rdx_r12(self):
        return self.__get_gadget_by_opcode("5a415cc3")

    def get_syscall(self):
        return self.__get_gadget_by_opcode("0f05c3")