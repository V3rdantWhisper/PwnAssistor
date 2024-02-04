from PwnAssistor.solver.LibcGot import LibcGotSover

sover = LibcGotSover("/home/nemo/Pwn/glibc-all-in-one/libs/2.38-3ubuntu1_amd64/libc.so.6", ["printf", "puts", "strncpy", "strcpy"], "./outputs/")

sover.Solver()
