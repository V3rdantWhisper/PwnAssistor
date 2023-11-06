# PwnAssistor

Auto tools for pwn, including fmt, heap, and so on.

## Develop planning

- [x] fmt: generate fmt payload for fmt(including fmtstr on the stack and else)
- [ ] heap
  - [x] generate house of apple and lys payload(including orw and getshell)
  - [x] recv leak address 
  - [ ] heap fengshui 
- [ ] stack
  - [ ] rop: generate rop payload 
  - [ ] pivot: generate pivot payload 
  - [ ] ret2csu: generate ret2csu payload 
  - [ ] ret2dl_reslove: generate ret2dl_reslove payload 
  - [ ] SROP: generate SROP payload 
- [ ] shellcode
  - [ ] generate shellcode payload 
  - [ ] generate shellcode payload with encode 1
  - [ ] generate shellcode payload with constraint
- [ ] Sover : use angr to detect valuable attack chain
  - [x] libc got sover : auto detect which libc got could use to hijack
  - [ ] FSOP sover : auto detect which file stream could use to hijack
- [ ] fuzz framework
