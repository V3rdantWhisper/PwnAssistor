from PwnAssistor.solver.LibcGot import LibcGotSover

sover = LibcGotSover("/home/nemo/Pwn/workspace/2024l3h/treasure_hunter/libc.so.6", ["free"], "./outputs/")

sover.Solver()
