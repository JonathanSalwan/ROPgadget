from capstone import *

code = b"\x19\xa8"


md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64)

#seem that \x82\x80 = ret isn't supported by capstone yet
for i in md.disasm(code, 0x1000000):
    print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

