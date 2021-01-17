## -*- coding: utf-8 -*-
##
##  Christoffer Brodd-Reijer - 2014-07-20 - ROPgadget tool
##
##  http://twitter.com/ephracis
##  http://shell-storm.org/project/ROPgadget/
##

import sys
from binascii import *
from ctypes import *

from capstone import *

from ropgadget.loaders.macho import *


class FAT_HEADER(BigEndianStructure):
    _fields_ = [
                ("magic",           c_uint),
                ("nfat_arch",       c_uint),
               ]


class FAT_ARC(BigEndianStructure):
    _fields_ = [
                ("cputype",         c_uint),
                ("cpusubtype",      c_uint),
                ("offset",          c_uint),
                ("size",            c_uint),
                ("align",           c_uint),
               ]


class MACHOFlags(object):
    CPU_TYPE_I386               = 0x7
    CPU_TYPE_X86_64             = (CPU_TYPE_I386 | 0x1000000)
    CPU_TYPE_MIPS               = 0x8
    CPU_TYPE_ARM                = 12
    CPU_TYPE_SPARC              = 14
    CPU_TYPE_POWERPC            = 18
    CPU_TYPE_POWERPC64          = (CPU_TYPE_POWERPC | 0x1000000)
    LC_SEGMENT                  = 0x1
    LC_SEGMENT_64               = 0x19
    S_ATTR_SOME_INSTRUCTIONS    = 0x00000400
    S_ATTR_PURE_INSTRUCTIONS    = 0x80000000


class UNIVERSAL(object):
    """This class parses the Universal binary."""

    def __init__(self, binary):
        self.__binary = bytearray(binary)
        self.__machoBinaries = []

        self.__fatHeader    = None
        self.__rawLoadCmd   = None
        self.__sections_l   = []

        self.__setHeader()
        self.__setBinaries()

    def __setHeader(self):
        self.__fatHeader = FAT_HEADER.from_buffer_copy(self.__binary)

    def __setBinaries(self):
        offset = 8
        for i in xrange(self.__fatHeader.nfat_arch):
            header = FAT_ARC.from_buffer_copy(self.__binary[offset:])
            rawBinary = self.__binary[header.offset:header.offset + header.size]
            if rawBinary[:4] == unhexlify(b"cefaedfe") or rawBinary[:4] == unhexlify(b"cffaedfe"):
                self.__machoBinaries.append(MACHO(rawBinary))
            else:
                print("[Error] Binary #" + str(i + 1) + " in Universal binary has an unsupported format")
            offset += sizeof(header)

    def getExecSections(self):
        ret = []
        for binary in self.__machoBinaries:
            ret += binary.getExecSections()
        return ret

    def getDataSections(self):
        ret = []
        for binary in self.__machoBinaries:
            ret += binary.getDataSections()
        return ret

    def getFormat(self):
        return "Universal"

    # TODO: These three will just return whatever is in the first binary.
    # Perhaps the rest of ROPgadget should support loading multiple binaries?
    def getEntryPoint(self):
        for binary in self.__machoBinaries:
            return binary.getEntryPoint()

    def getArch(self):
        for binary in self.__machoBinaries:
            return binary.getArch()

    def getArchMode(self):
        for binary in self.__machoBinaries:
            return binary.getArchMode()

    def getEndian(self):
        for binary in self.__machoBinaries:
            return binary.getEndian()


if sys.version_info.major == 3:
    xrange = range
