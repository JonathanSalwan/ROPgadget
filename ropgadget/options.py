## -*- coding: utf-8 -*-
##
##  Jonathan Salwan - 2014-05-17 - ROPgadget tool
## 
##  http://twitter.com/JonathanSalwan
##  http://shell-storm.org/project/ROPgadget/
## 
##  This program is free software: you can redistribute it and/or modify
##  it under the terms of the GNU General Public License as published by
##  the Free Software  Foundation, either  version 3 of  the License, or
##  (at your option) any later version.

import re
import codecs
from capstone   import CS_MODE_32
from struct     import pack

class Options:
    def __init__(self, options, binary, gadgets):
        self.__options = options
        self.__gadgets = gadgets
        self.__binary  = binary 

        if options.filter:   self.__filterOption()
        if options.only:     self.__onlyOption()
        if options.range:    self.__rangeOption()
        if options.re:       self.__reOption()
        if options.badbytes: self.__deleteBadBytes()

    def __filterOption(self):
        new = []
        if not self.__options.filter:
            return 
        filt = self.__options.filter.split("|")
        if not len(filt):
            return 
        for gadget in self.__gadgets:
            flag = 0
            insts = gadget["gadget"].split(" ; ")
            for ins in insts:
                if ins.split(" ")[0] in filt:
                    flag = 1
                    break
            if not flag:
                new += [gadget]
        self.__gadgets = new

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
            if vaddr >= rangeS and vaddr <= rangeE:
                new += [gadget]
        self.__gadgets = new

    def __reOption(self):
        new = []
        if not self.__options.re:
            return
        if '|' in self.__options.re:
            re_strs = self.__options.re.split(' | ')
            if 1 == len(re_strs):
                re_strs = self.__options.re.split('|')
        else:
            re_strs = self.__options.re

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

    def __deleteBadBytes(self):
        if not self.__options.badbytes:
            return
        new = []
        #Filter out empty badbytes (i.e if badbytes was set to 00|ff| there's an empty badbyte after the last '|')
        #and convert each one to the corresponding byte
        bbytes = [codecs.decode(bb.encode("ascii"), "hex") for bb in self.__options.badbytes.split("|") if bb]
        archMode = self.__binary.getArchMode()
        for gadget in self.__gadgets:
            gadAddr = pack("<L", gadget["vaddr"]) if archMode == CS_MODE_32 else pack("<Q", gadget["vaddr"])
            try:
                for x in bbytes:
                    if x in gadAddr: raise
                new += [gadget]
            except:
                pass
        self.__gadgets = new

    def getGadgets(self):
        return self.__gadgets

