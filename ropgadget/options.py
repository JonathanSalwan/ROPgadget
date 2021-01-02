## -*- coding: utf-8 -*-
##
##  Jonathan Salwan - 2014-05-17 - ROPgadget tool
##
##  http://twitter.com/JonathanSalwan
##  http://shell-storm.org/project/ROPgadget/
##

import codecs
import re
from struct import pack

from capstone import *


class Options(object):
    def __init__(self, options, binary, gadgets):
        self.__options = options
        self.__gadgets = gadgets
        self.__binary  = binary

        if options.only:
            self.__onlyOption()
        if options.range:
            self.__rangeOption()
        if options.re:
            self.__reOption()
        if options.badbytes:
            self.__deleteBadBytes()
        if options.callPreceded:
            self.__removeNonCallPreceded()

    def __onlyOption(self):
        new = []
        if not self.__options.only:
            return
        only = self.__options.only.split("|")
        if not len(only):
            return
        for gadget in self.__gadgets:
            flag = 0
            insts = gadget["gadget"].split(" ; ")
            for ins in insts:
                if ins.split(" ")[0] not in only:
                    flag = 1
                    break
            if not flag:
                new += [gadget]
        self.__gadgets = new

    def __rangeOption(self):
        new = []
        rangeS = int(self.__options.range.split('-')[0], 16)
        rangeE = int(self.__options.range.split('-')[1], 16)
        if rangeS == 0 and rangeE == 0:
            return
        for gadget in self.__gadgets:
            vaddr = gadget["vaddr"]
            if rangeS <= vaddr <= rangeE:
                new += [gadget]
        self.__gadgets = new

    def __reOption(self):
        new = []
        re_strs = []

        if not self.__options.re:
            return

        if '|' in self.__options.re:
            re_strs = self.__options.re.split(' | ')
            if len(re_strs) == 1:
                re_strs = self.__options.re.split('|')
        else:
            re_strs.append(self.__options.re)

        patterns = []
        for __re_str in re_strs:
            pattern = re.compile(__re_str)
            patterns.append(pattern)

        for gadget in self.__gadgets:
            flag = 1
            insts = gadget["gadget"].split(" ; ")
            for pattern in patterns:
                for ins in insts:
                    res = pattern.search(ins)
                    if res:
                        flag = 1
                        break
                    else:
                        flag = 0
                if not flag:
                    break
            if flag:
                new += [gadget]
        self.__gadgets = new

    def __removeNonCallPreceded(self):
        def __isGadgetCallPreceded(gadget):
            # Given a gadget, determine if the bytes immediately preceding are a call instruction
            prevBytes = gadget["prev"]
            # TODO: Improve / Semantically document each of these cases.
            callPrecededExpressions = [
                "\xe8[\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]$",
                "\xe8[\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]$",
                "\xff[\x00-\xff]$",
                "\xff[\x00-\xff][\x00-\xff]$",
                "\xff[\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]$",
                "\xff[\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]$",
            ]
            return bool(reduce(lambda x, y: x or y, map(lambda x: re.search(x, prevBytes), callPrecededExpressions)))
        arch = self.__binary.getArch()
        if arch == CS_ARCH_X86:
            initial_length = len(self.__gadgets)
            self.__gadgets = filter(__isGadgetCallPreceded, self.__gadgets)
            print("Options().removeNonCallPreceded(): Filtered out {} gadgets.".format(initial_length - len(self.__gadgets)))
        else:
            print("Options().removeNonCallPreceded(): Unsupported architecture.")

    def __deleteBadBytes(self):
        archMode = self.__binary.getArchMode()
        if not self.__options.badbytes:
            return
        new = []
        # Filter out empty badbytes (i.e if badbytes was set to 00|ff| there's an empty badbyte after the last '|')
        # and convert each one to the corresponding byte
        bbytes = []
        for bb in self.__options.badbytes.split("|"):
            if '-' in bb:
                rng = bb.split('-')
                low = ord(codecs.decode(rng[0], "hex"))
                high = ord(codecs.decode(rng[1], "hex"))
                for i in range(low, high):
                    bbytes.append(chr(i))
            else:
                bbytes.append(codecs.decode(bb.encode("ascii"), "hex"))

        archMode = self.__binary.getArchMode()
        for gadget in self.__gadgets:
            gadAddr = pack("<L", gadget["vaddr"]) if archMode == CS_MODE_32 else pack("<Q", gadget["vaddr"])
            try:
                for x in bbytes:
                    if x in gadAddr:
                        raise
                new += [gadget]
            except:
                pass
        self.__gadgets = new

    def getGadgets(self):
        return self.__gadgets
