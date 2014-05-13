#!/usr/bin/env python2
## -*- coding: utf-8 -*-
##
##  Jonathan Salwan - 2014-05-12 - ROPgadget tool
## 
##  http://twitter.com/JonathanSalwan
##  http://shell-storm.org/project/ROPgadget/
## 
##  This program is free software: you can redistribute it and/or modify
##  it under the terms of the GNU General Public License as published by
##  the Free Software  Foundation, either  version 3 of  the License, or
##  (at your option) any later version.

from loaders.elf    import *
from loaders.pe     import *
from loaders.raw    import *
from loaders.macho  import *

class Binary:
    def __init__(self, options):
        self.__fileName  = options.binary
        self.__rawBinary = None
        self.__binary    = None
        
        try:
            fd = open(self.__fileName, "rb")
            self.__rawBinary = fd.read()
            fd.close()
        except:
            print "[Error] Can't open the binary or binary not found"
            sys.exit(-1)

        if   options.rawArch and options.rawMode:
             self.__binary = Raw(self.__rawBinary, options.rawArch, options.rawMode)
        elif self.__rawBinary[:4] == "7f454c46".decode("hex"):
             self.__binary = ELF(self.__rawBinary)
        elif self.__rawBinary[:2] == "4d5a".decode("hex"):
             self.__binary = PE(self.__rawBinary)
        elif self.__rawBinary[:4] == "cefaedfe".decode("hex") or self.__rawBinary[:4] == "cffaedfe".decode("hex"):
             self.__binary = MACHO(self.__rawBinary)
        else:
            print "[Error] Binary format not supported"
            sys.exit(-1)

    def getFileName(self):
        return self.__fileName

    def getRawBinary(self):
        return self.__rawBinary

    def getEntryPoint(self):
        return self.__binary.getEntryPoint()

    def getDataSections(self):
        return self.__binary.getDataSections()

    def getExecSections(self):
        return self.__binary.getExecSections()

    def getArch(self):
        return self.__binary.getArch()

    def getArchMode(self):
        return self.__binary.getArchMode()

    def getFormat(self):
        return self.__binary.getFormat()

