## -*- coding: utf-8 -*-
##
##  Jonathan Salwan - 2014-05-12 - ROPgadget tool
##
##  http://twitter.com/JonathanSalwan
##  http://shell-storm.org/project/ROPgadget/
##

import re
from   capstone import *


class Gadgets:
    def __init__(self, binary, options, offset):
        self.__binary  = binary
        self.__options = options
        self.__offset  = offset


    def __checkInstructionBlackListedX86(self, insts):
        bl = ["db", "int3"]
        for inst in insts:
            for b in bl:
                if inst.split(" ")[0] == b:
                    return True
        return False

    def __checkMultiBr(self, insts, br):
        count = 0
        for inst in insts:
            if inst.split()[0] in br:
                count += 1
        return count

    def __passCleanX86(self, gadgets, multibr=False):
        new = []
        br = ["ret", "retf", "int", "sysenter", "jmp", "call", "syscall"]
        for gadget in gadgets:
            insts = gadget["gadget"].split(" ; ")
            if len(insts) == 1 and insts[0].split(" ")[0] not in br:
                continue
            if insts[-1].split(" ")[0] not in br:
                continue
            if self.__checkInstructionBlackListedX86(insts):
                continue
            if not multibr and self.__checkMultiBr(insts, br) > 1:
                continue
            if len([m.start() for m in re.finditer("ret", gadget["gadget"])]) > 1:
                continue
            new += [gadget]
        return new

    def __gadgetsFinding(self, section, gadgets, arch, mode):

        C_OP    = 0
        C_SIZE  = 1
        C_ALIGN = 2
        PREV_BYTES = 9 # Number of bytes prior to the gadget to store.
        ret = []
        md = Cs(arch, mode)
        for gad in gadgets:
            allRefRet = [m.start() for m in re.finditer(gad[C_OP], section["opcodes"])]
            for ref in allRefRet:
                for i in range(self.__options.depth):
                    if (section["vaddr"]+ref-(i*gad[C_ALIGN])) % gad[C_ALIGN] == 0:
                        decodes = md.disasm(section["opcodes"][ref-(i*gad[C_ALIGN]):ref+gad[C_SIZE]], section["vaddr"]+ref)
                        gadget = ""
                        for decode in decodes:
                            gadget += (decode.mnemonic + " " + decode.op_str + " ; ").replace("  ", " ")
                        if re.search(gad[C_OP],decode.bytes) is None:
                                continue
                        if len(gadget) > 0:
                            gadget = gadget[:-3]
                            off = self.__offset
                            vaddr = off+section["vaddr"]+ref-(i*gad[C_ALIGN])
                            prevBytesAddr = max(section["vaddr"], vaddr - PREV_BYTES)
                            prevBytes = section["opcodes"][prevBytesAddr-section["vaddr"]:vaddr-section["vaddr"]]
                            ret += [{"vaddr" :  vaddr, "gadget" : gadget, "decodes" : decodes, "bytes": section["opcodes"][ref-(i*gad[C_ALIGN]):ref+gad[C_SIZE]], "prev": prevBytes}]
        return ret

    def addROPGadgets(self, section):

        arch = self.__binary.getArch()
        arch_mode = self.__binary.getArchMode()

        if arch == CS_ARCH_X86:
            gadgets = [
                            [b"\xc3", 1, 1],               # ret
                            [b"\xc2[\x00-\xff]{2}", 3, 1], # ret <imm>
                            [b"\xcb", 1, 1],               # retf
                            [b"\xca[\x00-\xff]{2}", 3, 1],  # retf <imm>
                            # MPX
                            [b"\xf2\xc3", 2, 1],               # ret
                            [b"\xf2\xc2[\x00-\xff]{2}", 4, 1], # ret <imm>
                       ]

        elif arch == CS_ARCH_MIPS:   gadgets = []            # MIPS doesn't contains RET instruction set. Only JOP gadgets
        elif arch == CS_ARCH_PPC:
            gadgets = [
                            [b"\x4e\x80\x00\x20", 4, 4] # blr
                       ]
            arch_mode = arch_mode + CS_MODE_BIG_ENDIAN

        elif arch == CS_ARCH_SPARC:
            gadgets = [
                            [b"\x81\xc3\xe0\x08", 4, 4], # retl
                            [b"\x81\xc7\xe0\x08", 4, 4], # ret
                            [b"\x81\xe8\x00\x00", 4, 4]  # restore
                       ]
            arch_mode = CS_MODE_BIG_ENDIAN

        elif arch == CS_ARCH_ARM:    gadgets = []            # ARM doesn't contains RET instruction set. Only JOP gadgets
        elif arch == CS_ARCH_ARM64:
            gadgets =  [
                            [b"\xc0\x03\x5f\xd6", 4, 4] # ret
                       ]
            arch_mode = CS_MODE_ARM

        else:
            print("Gadgets().addROPGadgets() - Architecture not supported")
            return None

        if len(gadgets) > 0 :
            return self.__gadgetsFinding(section, gadgets, arch, arch_mode)
        return gadgets


    def addJOPGadgets(self, section):
        arch = self.__binary.getArch()
        arch_mode = self.__binary.getArchMode()



        if arch  == CS_ARCH_X86:
            gadgets = [
                               [b"\xff[\x20\x21\x22\x23\x26\x27]{1}", 2, 1],     # jmp  [reg]
                               [b"\xff[\xe0\xe1\xe2\xe3\xe4\xe6\xe7]{1}", 2, 1], # jmp  [reg]
                               [b"\xff[\x10\x11\x12\x13\x16\x17]{1}", 2, 1],     # jmp  [reg]
                               [b"\xff[\xd0\xd1\xd2\xd3\xd4\xd6\xd7]{1}", 2, 1],  # call [reg]
                               # MPX
                               [b"\xf2\xff[\x20\x21\x22\x23\x26\x27]{1}", 3, 1],     # jmp  [reg]
                               [b"\xf2\xff[\xe0\xe1\xe2\xe3\xe4\xe6\xe7]{1}", 3, 1], # jmp  [reg]
                               [b"\xf2\xff[\x10\x11\x12\x13\x16\x17]{1}", 3, 1],     # jmp  [reg]
                               [b"\xf2\xff[\xd0\xd1\xd2\xd3\xd4\xd6\xd7]{1}", 3, 1]  # call [reg]
                      ]


        elif arch == CS_ARCH_MIPS:
            gadgets = [
                               [b"\x09\xf8\x20\x03[\x00-\xff]{4}", 8, 4], # jrl $t9
                               [b"\x08\x00\x20\x03[\x00-\xff]{4}", 8, 4], # jr  $t9
                               [b"\x08\x00\xe0\x03[\x00-\xff]{4}", 8, 4]  # jr  $ra
                      ]
        elif arch == CS_ARCH_PPC:    gadgets = [] # PPC architecture doesn't contains reg branch instruction
        elif arch == CS_ARCH_SPARC:
            gadgets = [
                               [b"\x81\xc0[\x00\x40\x80\xc0]{1}\x00", 4, 4]  # jmp %g[0-3]
                      ]
            arch_mode = CS_MODE_BIG_ENDIAN
        elif arch == CS_ARCH_ARM64:
            gadgets = [
                               [b"[\x00\x20\x40\x60\x80\xa0\xc0\xe0]{1}[\x00\x01\x02]{1}\x1f\xd6", 4, 4],     # br  reg
                               [b"[\x00\x20\x40\x60\x80\xa0\xc0\xe0]{1}[\x00\x01\x02]{1}\x5C\x3f\xd6", 4, 4]  # blr reg
                      ]
            arch_mode = CS_MODE_ARM
        elif arch == CS_ARCH_ARM:
            if self.__options.thumb or self.__options.rawMode == "thumb":
                gadgets = [
                               [b"[\x00\x08\x10\x18\x20\x28\x30\x38\x40\x48\x70]{1}\x47", 2, 2], # bx   reg
                               [b"[\x80\x88\x90\x98\xa0\xa8\xb0\xb8\xc0\xc8\xf0]{1}\x47", 2, 2], # blx  reg
                               [b"[\x00-\xff]{1}\xbd", 2, 2]                                     # pop {,pc}
                          ]
                arch_mode = CS_MODE_THUMB
            else:
                gadgets = [
                               [b"[\x10-\x19\x1e]{1}\xff\x2f\xe1", 4, 4],  # bx   reg
                               [b"[\x30-\x39\x3e]{1}\xff\x2f\xe1", 4, 4],  # blx  reg
                               [b"[\x00-\xff]{1}\x80\xbd\xe8", 4, 4]       # pop {,pc}
                          ]
                arch_mode = CS_MODE_ARM
        else:
            print("Gadgets().addJOPGadgets() - Architecture not supported")
            return None

        if len(gadgets) > 0 :
            return self.__gadgetsFinding(section, gadgets, arch, arch_mode)
        return gadgets

    def addSYSGadgets(self, section):

        arch = self.__binary.getArch()
        arch_mode = self.__binary.getArchMode()

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
            gadgets = [
                               [b"\x0c\x00\x00\x00", 4, 4] # syscall
                      ]
        elif arch == CS_ARCH_PPC:    gadgets = [] # TODO (sc inst)
        elif arch == CS_ARCH_SPARC:  gadgets = [] # TODO (ta inst)
        elif arch == CS_ARCH_ARM64:  gadgets = [] # TODO
        elif arch == CS_ARCH_ARM:
            if self.__options.thumb or self.__options.rawMode == "thumb":
                gadgets = [
                               [b"\x00-\xff]{1}\xef", 2, 2] # svc
                          ]
                arch_mode = CS_MODE_THUMB
            else:
                gadgets = [
                               [b"\x00-\xff]{3}\xef", 4, 4] # svc
                          ]
                arch_mode = CS_MODE_ARM
        else:
            print("Gadgets().addSYSGadgets() - Architecture not supported")
            return None

        if len(gadgets) > 0 :
            return self.__gadgetsFinding(section, gadgets, arch, arch_mode)
        return []


    def passClean(self, gadgets, multibr):

        arch = self.__binary.getArch()
        if   arch == CS_ARCH_X86:    return self.__passCleanX86(gadgets, multibr)
        elif arch == CS_ARCH_MIPS:   return gadgets
        elif arch == CS_ARCH_PPC:    return gadgets
        elif arch == CS_ARCH_SPARC:  return gadgets
        elif arch == CS_ARCH_ARM:    return gadgets
        elif arch == CS_ARCH_ARM64:  return gadgets
        else:
            print("Gadgets().passClean() - Architecture not supported")
            return None

