from pwn import u64, ELF, log
import time
import angr
import claripy


class LibcGotSover:
    TIMEOUT = 60
    MAX_STEP = 1000

    def __init__(self, libc_path: str, targets: list, out_dir: str) -> None:
        self.output_dir = out_dir
        self.targets = targets
        self.libc_path = libc_path
        self.libc_obj = ELF(libc_path)
        self.symbols = {}
        self.got_claripy = None
        self.got_addr = 0
        self.got_size = 0
        self.__get_symbols()
        self.__init_got()
        self.proj = angr.Project(libc_path, main_opts={"base_addr": 0})

    def __init_got(self) -> None:
        for i in self.libc_obj.sections:
            if i.name == ".got.plt":
                self.got_addr = i.header.sh_addr
                self.got_size = i.header.sh_size
                self.got_claripy = claripy.BVS(
                    "got_claripy", i.header.sh_size * 8, explicit_name=True)
        if self.got_claripy is None:
            for i in self.libc_obj.sections:
                if i.name == ".got":
                    self.got_addr = i.header.sh_addr
                    self.got_size = i.header.sh_size
                    self.got_claripy = claripy.BVS(
                        "got_claripy", i.header.sh_size * 8, explicit_name=True)

    def __get_symbols(self) -> None:
        for sym_name in self.targets:
            self.symbols[sym_name] = self.libc_obj.symbols[sym_name]

    @staticmethod
    def __process_record(got_bytes):
        # byte to str:
        out_str = ""
        offset = 0
        for i in range(len(got_bytes) // 8):
            num = u64(got_bytes[i * 8:i * 8 + 8])
            out_str += "0x%016x\n" % num
            if num == 0x67616c66646e6966:
                offset = i
        return out_str, offset

    def Solver(self):
        for sym_name, addr in self.symbols.items():
            self.__solver(sym_name, addr)

    def __solver(self, name, addr):
        state = self.proj.factory.entry_state(addr=addr)
        reg_list = [
            x for x in state.arch.default_symbolic_registers if x not in ['rip', 'rsp']]
        for reg in reg_list:
            setattr(state.regs, reg, claripy.BVS(
                f"orig_{reg}", 8 * 8, explicit_name=True))
        state.stack_push(0x41414141)
        state.options.add(angr.sim_options.SYMBOLIC_WRITE_ADDRESSES)
        state.options.add(angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
        state.options.add(angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
        state.regs.rdi = 0x5000000
        state.memory.store(state.regs.rdi, b"/bin/sh\x00")
        state.memory.store(self.got_addr, self.got_claripy)

        simgr = self.proj.factory.simgr(state, save_unconstrained=True)
        simgr.stashes['avoided'] = []
        simgr.stashes['bad'] = []
        simgr.stashes['unconstrained'] = []
        simgr.stashes['found'] = []
        step = 0

        while not simgr.found:
            if (not simgr.active) and (not simgr.unconstrained):
                break
            start = time.time()
            simgr.step()
            elapsed_time = time.time() - start
            simgr.move("active", "deadended",
                       filter_func=lambda s: s.addr == 0x41414141)
            simgr.move("active", "errored",
                       filter_func=lambda s: self.proj.loader.find_segment_containing(s.addr) is None)
            simgr.move(from_stash='unconstrained',
                       to_stash='found',
                       filter_func=filter_func)

            log.info(f"time: {elapsed_time}")
            print(simgr)
            step += 1

            if simgr.found:
                print("-----------------------------------")
                print(
                    f"Found {len(simgr.found)} targets states while processing {name}")
                print("-----------------------------------")
                solution_state = simgr.found[0]
                print_good_addr = 0x67616c66646e6966
                solution_state.add_constraints(
                    solution_state.regs.rip == print_good_addr)

                sovered_got = solution_state.solver.eval(
                    solution_state.memory.load(self.got_addr, self.got_size), cast_to=bytes)
                output_str, offset = LibcGotSover.__process_record(sovered_got)

                with open(f"{self.output_dir}/{name}.txt", "w") as f:
                    f.write("target address :" + hex(self.got_addr + offset * 8) + "\n")
                    f.write("target name :" + name + "\n\n")
                    f.write("solution state:\n")
                    f.write(output_str)

def filter_func(state):
    target_addr = 0x67616c66646e6966
    return state.satisfiable(extra_constraints=(state.regs.rip == target_addr, state.regs.rdi == 0x5000000,))
