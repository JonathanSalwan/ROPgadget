## -*- coding: utf-8 -*-
##
##  Jonathan Salwan - 2014-05-12 - ROPgadget tool
##
##  http://twitter.com/JonathanSalwan
##  http://shell-storm.org/project/ROPgadget/
##

import re

from capstone import *


class Gadgets(object):
    def __init__(self, binary, options, offset):
        self.__binary  = binary
        self.__options = options
        self.__offset  = offset
        self.__arch = self.__binary.getArch()

        re_str = ""
        if self.__arch == CS_ARCH_X86:
            re_str = "db|int3"
        elif self.__arch == CS_ARCH_ARM64:
            re_str = "brk|smc|hvc"
        if self.__options.filter:
            if re_str:
                re_str += "|"
            re_str += self.__options.filter

        self.__filterRE = re.compile("({})$".format(re_str)) if re_str else None

    def __passCleanX86(self, decodes):
        br = ["ret", "retf", "int", "sysenter", "jmp", "call", "syscall"]

        if decodes[-1][2] not in br:
            return True
        if not self.__options.multibr and any(mnemonic in br for _, _, mnemonic, _ in decodes[:-1]):
            return True
        if any("ret" in mnemonic for _, _, mnemonic, _ in decodes[:-1]):
            return True

        return False

    def __gadgetsFinding(self, section, gadgets, arch, mode):

        PREV_BYTES = 9  # Number of bytes prior to the gadget to store.

        opcodes = section["opcodes"]
        sec_vaddr = section["vaddr"]

        ret = []
        md = Cs(arch, mode)
        for gad_op, gad_size, gad_align in gadgets:
            if self.__options.align:
                gad_align = self.__options.align
            allRefRet = [m.start() for m in re.finditer(gad_op, opcodes)]
            for ref in allRefRet:
                end = ref + gad_size
                for i in range(self.__options.depth):
                    start = ref - (i * gad_align)
                    if (sec_vaddr + start) % gad_align == 0:
                        code = opcodes[start:end]
                        decodes = md.disasm_lite(code, sec_vaddr + start)
                        decodes = list(decodes)
                        if sum(size for _, size, _, _ in decodes) != i * gad_align + gad_size:
                            # We've read less instructions than planned so something went wrong
                            continue
                        if self.passClean(decodes):
                            continue
                        off = self.__offset
                        vaddr = off + sec_vaddr + start
                        g = {"vaddr": vaddr}
                        if not self.__options.noinstr:
                            g["gadget"] = " ; ".join("{}{}{}".format(mnemonic, " " if op_str else "", op_str)
                                                     for _, _, mnemonic, op_str in decodes).replace("  ", " ")
                        if self.__options.callPreceded:
                            prevBytesAddr = max(sec_vaddr, vaddr - PREV_BYTES)
                            g["prev"] = opcodes[prevBytesAddr - sec_vaddr:vaddr - sec_vaddr]
                        if self.__options.dump:
                            g["bytes"] = code
                        ret.append(g)
        return ret

    def addROPGadgets(self, section):

        arch = self.__binary.getArch()
        arch_mode = self.__binary.getArchMode()
        arch_endian = self.__binary.getEndian()

        if arch == CS_ARCH_X86:
            gadgets = [
                            [b"\xc3", 1, 1],                # ret
                            [b"\xc2[\x00-\xff]{2}", 3, 1],  # ret <imm>
                            [b"\xcb", 1, 1],                # retf
                            [b"\xca[\x00-\xff]{2}", 3, 1],  # retf <imm>
                            # MPX
                            [b"\xf2\xc3", 2, 1],                # ret
                            [b"\xf2\xc2[\x00-\xff]{2}", 4, 1],  # ret <imm>
                       ]

        elif arch == CS_ARCH_MIPS:
            gadgets = []  # MIPS doesn't have RET instructions. Only JOP gadgets
        elif arch == CS_ARCH_PPC:
            if arch_endian == CS_MODE_BIG_ENDIAN:
                gadgets = [
                               [b"\x4e\x80\x00\x20", 4, 4] # blr
                          ]
            else:
                gadgets = [
                               [b"\x20\x00\x80\x4e", 4, 4] # blr
                          ]

        elif arch == CS_ARCH_SPARC:
            if arch_endian == CS_MODE_BIG_ENDIAN:
                gadgets = [
                               [b"\x81\xc3\xe0\x08", 4, 4], # retl
                               [b"\x81\xc7\xe0\x08", 4, 4], # ret
                               [b"\x81\xe8\x00\x00", 4, 4]  # restore
                          ]
            else:
                gadgets = [
                               [b"\x08\xe0\xc3\x81", 4, 4], # retl
                               [b"\x08\xe0\xc7\x81", 4, 4], # ret
                               [b"\x00\x00\xe8\x81", 4, 4]  # restore
                          ]
            arch_mode = 0

        elif arch == CS_ARCH_ARM:
            gadgets = []  # ARM doesn't have RET instructions. Only JOP gadgets
        elif arch == CS_ARCH_ARM64:
            if arch_endian == CS_MODE_BIG_ENDIAN:
                gadgets = [
                               [b"\xd6\x5f\x03\xc0", 4, 4] # ret
                          ]
            else:
                gadgets = [
                               [b"\xc0\x03\x5f\xd6", 4, 4] # ret
                          ]
            arch_mode = CS_MODE_ARM

        else:
            print("Gadgets().addROPGadgets() - Architecture not supported")
            return None

        if gadgets:
            return self.__gadgetsFinding(section, gadgets, arch, arch_mode + arch_endian)
        return gadgets

    def addJOPGadgets(self, section):
        arch = self.__binary.getArch()
        arch_mode = self.__binary.getArchMode()
        arch_endian = self.__binary.getEndian()

        if arch  == CS_ARCH_X86:
            # we start with x86 and x64 common sequences operating on registers
            gadgets = [
                               # call/jmp reg
                               # d0-d7=call,e0-e7=jmp
                               # x86: 0=eax,1=ecx,2=edx,3=ebx,4=esp,5=ebp,6=esi,7=edi
                               # x64: 0=rax,1=rcx,2=rdx,3=rbx,4=rsp,5=rbp,6=rsi,7=rdi
                               [b"\xff[\xd0-\xd7\xe0-\xe7]", 2, 1],

                               # call/jmp [reg]
                               # 10-17=call,20-27=jmp
                               # x86: 0=eax,1=ecx,2=edx,3=ebx,            6=esi,7=edi
                               # x64: 0=rax,1=rcx,2=rdx,3=rbx,            6=rsi,7=rdi
                               [b"\xff[\x10-\x13\x16-\x17\x20-\x23\x26-\x27]", 2, 1],
                               # call/jmp [reg]
                               # 14=call,24=jmp
                               # x86: esp
                               # x64: rsp
                               [b"\xff[\x14\x24]\x24", 3, 1],

                               # call/jmp [reg + offset], -0x80 <= offset <= 0x7f
                               # 50-57=call,60-67=jmp
                               # x86: 0=eax,1=ecx,2=edx,3=ebx,      5=ebp,6=esi,7=edi
                               # x64: 0=rax,1=rcx,2=rdx,3=rbx,      5=rbp,6=rsi,7=rdi
                               [b"\xff[\x50-\x53\x55-\x57\x60-\x63\x65-\x67][\x00-\xff]", 3, 1],
                               # call/jmp [reg + offset], -0x80 <= offset <= 0x7f
                               # 54=call,64=jmp
                               # x86: esp
                               # x64: rsp
                               [b"\xff[\x54\x64]\x24[\x00-\xff]", 4, 1],

                               # call/jmp [reg + offset], -0x80000000 <= offset <= 0x7fffffff
                               # 90-97=call,a0-a7=jmp
                               # x86: 0=eax,1=ecx,2=edx,3=ebx,      5=ebp,6=esi,7=edi
                               # x64: 0=rax,1=rcx,2=rdx,3=rbx,      5=rbp,6=rsi,7=rdi
                               [b"\xff[\x90-\x93\x95-\x97\xa0-\xa3\xa5-\xa7][\x00-\xff]{4}", 6, 1],
                               # call/jmp [reg + offset], -0x80000000 <= offset <= 0x7fffffff
                               # 94=call,a4=jmp
                               # x86: esp
                               # x64: rsp
                               [b"\xff[\x94\xa4]\x24[\x00-\xff]{4}", 7, 1]
                      ]
            # in x64, by adding 41 before a sequence with
            # 0=rax,1=rcx,2=rdx,3=rbx,4=rsp,5=rbp,6=rsi,7=rdi
            # we convert it to the same sequence with
            # 0= r8,1= r9,2=r10,3=r11,4=r12,5=r13,6=r14,7=r15
            if arch_mode == CS_MODE_64:
                gadgets += [(b"\x41" + op, size + 1, align) for (op, size, align) in gadgets]
            # finally, add extra sequences common to x86 and x64
            gadgets += [
                               [b"\xeb[\x00-\xff]", 2, 1],                        # jmp offset
                               [b"\xe9[\x00-\xff]{4}", 5, 1],                     # jmp offset
                               # MPX
                               [b"\xf2\xff[\x20\x21\x22\x23\x26\x27]{1}", 3, 1],     # jmp  [reg]
                               [b"\xf2\xff[\xe0\xe1\xe2\xe3\xe4\xe6\xe7]{1}", 3, 1], # jmp  [reg]
                               [b"\xf2\xff[\x10\x11\x12\x13\x16\x17]{1}", 3, 1],     # jmp  [reg]
                               [b"\xf2\xff[\xd0\xd1\xd2\xd3\xd4\xd6\xd7]{1}", 3, 1]  # call [reg]
                       ]
        elif arch == CS_ARCH_MIPS:
            if arch_endian == CS_MODE_BIG_ENDIAN:
                gadgets = [
                               [b"\x00[\x40\x60\x80\xa0\xc0\xe0]\xf8\x09[\x00-\xff]{4}", 8, 4],               # jalr $v[0-1]|$a[0-3]
                               [b"[\x01\x02][\x00\x20\x40\x60\x80\xa0\xc0\xe0]\xf8\x09[\x00-\xff]{4}", 8, 4], # jalr $t[0-7]|$s[0-7]
                               [b"\x03[\x00\x20\xc0\xe0]\xf8\x09[\x00-\xff]{4}", 8, 4],                       # jalr $t[8-9]|$s8|$ra
                               [b"\x00[\x40\x60\x80\xa0\xc0\xe0]\x00\x08[\x00-\xff]{4}", 8, 4],               # jr $v[0-1]|$a[0-3]
                               [b"[\x01\x02][\x00\x20\x40\x60\x80\xa0\xc0\xe0]\x00\x08[\x00-\xff]{4}", 8, 4], # jr $t[0-7]|$s[0-7]
                               [b"\x03[\x00\x20\xc0\xe0]\x00\x08[\x00-\xff]{4}", 8, 4],                       # jr $t[8-9]|$s8|$ra
                               [b"[\x0c-\x0f][\x00-\xff]{7}", 8, 4],                                          # jal addr
                               [b"[\x08-\x0b][\x00-\xff]{7}", 8, 4]                                           # j addr
                          ]
            else:
                gadgets = [
                               [b"\x09\xf8[\x40\x60\x80\xa0\xc0\xe0]\x00[\x00-\xff]{4}", 8, 4],               # jalr $v[0-1]|$a[0-3]
                               [b"\x09\xf8[\x00\x20\x40\x60\x80\xa0\xc0\xe0][\x01\x02][\x00-\xff]{4}", 8, 4], # jalr $t[0-7]|$s[0-7]
                               [b"\x09\xf8[\x00\x20\xc0\xe0]\x03[\x00-\xff]{4}", 8, 4],                       # jalr $t[8-9]|$s8|$ra
                               [b"\x08\x00[\x40\x60\x80\xa0\xc0\xe0]\x00[\x00-\xff]{4}", 8, 4],               # jr $v[0-1]|$a[0-3]
                               [b"\x08\x00[\x00\x20\x40\x60\x80\xa0\xc0\xe0][\x01\x02][\x00-\xff]{4}", 8, 4], # jr $t[0-7]|$s[0-7]
                               [b"\x08\x00[\x00\x20\xc0\xe0]\x03[\x00-\xff]{4}", 8, 4],                       # jr $t[8-9]|$s8|$ra
                               [b"[\x00-\xff]{3}[\x0c-\x0f][\x00-\xff]{4}", 8, 4],                            # jal addr
                               [b"[\x00-\xff]{3}[\x08-\x0b][\x00-\xff]{4}", 8, 4]                             # j addr
                          ]
        elif arch == CS_ARCH_PPC:
            gadgets = []  # PPC doesn't have reg branch instructions
        elif arch == CS_ARCH_SPARC:
            if arch_endian == CS_MODE_BIG_ENDIAN:
                gadgets = [
                               [b"\x81\xc0[\x00\x40\x80\xc0]{1}\x00", 4, 4]  # jmp %g[0-3]
                          ]
            else:
                gadgets = [
                               [b"\x00[\x00\x40\x80\xc0]{1}\xc0\x81", 4, 4]  # jmp %g[0-3]
                          ]
            arch_mode = 0
        elif arch == CS_ARCH_ARM64:
            if arch_endian == CS_MODE_BIG_ENDIAN:
                gadgets = [
                               [b"\xd6[\x1f\x5f]{1}[\x00-\x03]{1}[\x00\x20\x40\x60\x80\xa0\xc0\xe0]{1}", 4, 4],  # br reg
                               [b"\xd6\?[\x00-\x03]{1}[\x00\x20\x40\x60\x80\xa0\xc0\xe0]{1}", 4, 4]  # blr reg # noqa: W605 # FIXME: \?
                          ]
            else:
                gadgets = [
                               [b"[\x00\x20\x40\x60\x80\xa0\xc0\xe0]{1}[\x00-\x03]{1}[\x1f\x5f]{1}\xd6", 4, 4],  # br reg
                               [b"[\x00\x20\x40\x60\x80\xa0\xc0\xe0]{1}[\x00-\x03]{1}\?\xd6", 4, 4]  # blr reg # noqa: W605 # FIXME: \?
                          ]
            arch_mode = CS_MODE_ARM
        elif arch == CS_ARCH_ARM:
            if self.__options.thumb or self.__options.rawMode == "thumb":
                if arch_endian == CS_MODE_BIG_ENDIAN:
                    gadgets = [
                               [b"\x47[\x00\x08\x10\x18\x20\x28\x30\x38\x40\x48\x70]{1}", 2, 2], # bx   reg
                               [b"\x47[\x80\x88\x90\x98\xa0\xa8\xb0\xb8\xc0\xc8\xf0]{1}", 2, 2], # blx  reg
                               [b"\xbd[\x00-\xff]{1}", 2, 2]                                     # pop {,pc}
                              ]
                else:
                    gadgets = [
                               [b"[\x00\x08\x10\x18\x20\x28\x30\x38\x40\x48\x70]{1}\x47", 2, 2], # bx   reg
                               [b"[\x80\x88\x90\x98\xa0\xa8\xb0\xb8\xc0\xc8\xf0]{1}\x47", 2, 2], # blx  reg
                               [b"[\x00-\xff]{1}\xbd", 2, 2]                                     # pop {,pc}
                              ]
                arch_mode = CS_MODE_THUMB
            else:
                if arch_endian == CS_MODE_BIG_ENDIAN:
                    gadgets = [
                               [b"\xe1\x2f\xff[\x10-\x19\x1e]{1}", 4, 4],  # bx   reg
                               [b"\xe1\x2f\xff[\x30-\x39\x3e]{1}", 4, 4],  # blx  reg
                               [b"[\xe8\xe9][\x10-\x1e\x30-\x3e\x50-\x5e\x70-\x7e\x90-\x9e\xb0-\xbe\xd0-\xde\xf0-\xfe][\x80-\xff][\x00-\xff]", 4, 4] # ldm {,pc}
                              ]
                else:
                    gadgets = [
                               [b"[\x10-\x19\x1e]{1}\xff\x2f\xe1", 4, 4],  # bx   reg
                               [b"[\x30-\x39\x3e]{1}\xff\x2f\xe1", 4, 4],  # blx  reg
                               [b"[\x00-\xff][\x80-\xff][\x10-\x1e\x30-\x3e\x50-\x5e\x70-\x7e\x90-\x9e\xb0-\xbe\xd0-\xde\xf0-\xfe][\xe8\xe9]", 4, 4] # ldm {,pc}
                              ]
                arch_mode = CS_MODE_ARM
        else:
            print("Gadgets().addJOPGadgets() - Architecture not supported")
            return None

        if gadgets:
            return self.__gadgetsFinding(section, gadgets, arch, arch_mode + arch_endian)
        return gadgets

    def addSYSGadgets(self, section):

        arch = self.__binary.getArch()
        arch_mode = self.__binary.getArchMode()
        arch_endian = self.__binary.getEndian()

        if   arch == CS_ARCH_X86:
            gadgets = [
                               [b"\xcd\x80", 2, 1],                         # int 0x80
                               [b"\x0f\x34", 2, 1],                         # sysenter
                               [b"\x0f\x05", 2, 1],                         # syscall
                               [b"\x65\xff\x15\x10\x00\x00\x00", 7, 1],     # call DWORD PTR gs:0x10
                               [b"\xcd\x80\xc3", 3, 1],                     # int 0x80 ; ret
                               [b"\x0f\x34\xc3", 3, 1],                     # sysenter ; ret
                               [b"\x0f\x05\xc3", 3, 1],                     # syscall ; ret
                               [b"\x65\xff\x15\x10\x00\x00\x00\xc3", 8, 1], # call DWORD PTR gs:0x10 ; ret
                      ]

        elif arch == CS_ARCH_MIPS:
            if arch_endian == CS_MODE_BIG_ENDIAN:
                gadgets = [
                               [b"\x00\x00\x00\x0c", 4, 4] # syscall
                          ]
            else:
                gadgets = [
                               [b"\x0c\x00\x00\x00", 4, 4] # syscall
                          ]
        elif arch == CS_ARCH_PPC:
            gadgets = [] # TODO (sc inst)
        elif arch == CS_ARCH_SPARC:
            gadgets = [] # TODO (ta inst)
        elif arch == CS_ARCH_ARM64:
            gadgets = [] # TODO
        elif arch == CS_ARCH_ARM:
            if self.__options.thumb or self.__options.rawMode == "thumb":
                gadgets = [
                               [b"\x00-\xff]{1}\xef", 2, 2] # FIXME: svc
                          ]
                arch_mode = CS_MODE_THUMB
            else:
                gadgets = [
                               [b"\x00-\xff]{3}\xef", 4, 4] # FIXME: svc
                          ]
                arch_mode = CS_MODE_ARM
        else:
            print("Gadgets().addSYSGadgets() - Architecture not supported")
            return None

        if gadgets:
            return self.__gadgetsFinding(section, gadgets, arch, arch_mode + arch_endian)
        return []

    def passClean(self, decodes):
        if not decodes:
            return True

        if self.__arch == CS_ARCH_X86 and self.__passCleanX86(decodes):
            return True

        if self.__filterRE and any(self.__filterRE.match(mnemonic) for _, _, mnemonic, _ in decodes):
            return True

        return False
