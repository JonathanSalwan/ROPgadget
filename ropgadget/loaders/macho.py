## -*- coding: utf-8 -*-
##
##  Jonathan Salwan - 2014-05-12 - ROPgadget tool
##
##  http://twitter.com/JonathanSalwan
##  http://shell-storm.org/project/ROPgadget/
##

from ctypes import *

from capstone import *


class MACH_HEADER_LE(LittleEndianStructure):
    _fields_ = [
                ("magic",           c_uint),
                ("cputype",         c_uint),
                ("cpusubtype",      c_uint),
                ("filetype",        c_uint),
                ("ncmds",           c_uint),
                ("sizeofcmds",      c_uint),
                ("flags",           c_uint),
               ]

class MACH_HEADER_BE(BigEndianStructure):
    _fields_ = [
                ("magic",           c_uint),
                ("cputype",         c_uint),
                ("cpusubtype",      c_uint),
                ("filetype",        c_uint),
                ("ncmds",           c_uint),
                ("sizeofcmds",      c_uint),
                ("flags",           c_uint),
               ]


class LOAD_COMMAND_LE(LittleEndianStructure):
    _fields_ = [
                ("cmd",             c_uint),
                ("cmdsize",         c_uint),
               ]

class LOAD_COMMAND_BE(BigEndianStructure):
    _fields_ = [
                ("cmd",             c_uint),
                ("cmdsize",         c_uint),
               ]


class SEGMENT_COMMAND_LE(LittleEndianStructure):
    _fields_ = [
                ("cmd",             c_uint),
                ("cmdsize",         c_uint),
                ("segname",         c_ubyte * 16),
                ("vmaddr",          c_uint),
                ("vmsize",          c_uint),
                ("fileoff",         c_uint),
                ("filesize",        c_uint),
                ("maxprot",         c_uint),
                ("initprot",        c_uint),
                ("nsects",          c_uint),
                ("flags",           c_uint),
               ]

class SEGMENT_COMMAND_BE(BigEndianStructure):
    _fields_ = [
                ("cmd",             c_uint),
                ("cmdsize",         c_uint),
                ("segname",         c_ubyte * 16),
                ("vmaddr",          c_uint),
                ("vmsize",          c_uint),
                ("fileoff",         c_uint),
                ("filesize",        c_uint),
                ("maxprot",         c_uint),
                ("initprot",        c_uint),
                ("nsects",          c_uint),
                ("flags",           c_uint),
               ]


class SEGMENT_COMMAND64_LE(LittleEndianStructure):
    _fields_ = [
                ("cmd",             c_uint),
                ("cmdsize",         c_uint),
                ("segname",         c_ubyte * 16),
                ("vmaddr",          c_ulonglong),
                ("vmsize",          c_ulonglong),
                ("fileoff",         c_ulonglong),
                ("filesize",        c_ulonglong),
                ("maxprot",         c_uint),
                ("initprot",        c_uint),
                ("nsects",          c_uint),
                ("flags",           c_uint),
               ]

class SEGMENT_COMMAND64_BE(BigEndianStructure):
    _fields_ = [
                ("cmd",             c_uint),
                ("cmdsize",         c_uint),
                ("segname",         c_ubyte * 16),
                ("vmaddr",          c_ulonglong),
                ("vmsize",          c_ulonglong),
                ("fileoff",         c_ulonglong),
                ("filesize",        c_ulonglong),
                ("maxprot",         c_uint),
                ("initprot",        c_uint),
                ("nsects",          c_uint),
                ("flags",           c_uint),
               ]


class SECTION_LE(LittleEndianStructure):
    _fields_ = [
                ("sectname",        c_ubyte * 16),
                ("segname",         c_ubyte * 16),
                ("addr",            c_uint),
                ("size",            c_uint),
                ("offset",          c_uint),
                ("align",           c_uint),
                ("reloff",          c_uint),
                ("nreloc",          c_uint),
                ("flags",           c_uint),
                ("reserved1",       c_uint),
                ("reserved2",       c_uint),
               ]

class SECTION_BE(BigEndianStructure):
    _fields_ = [
                ("sectname",        c_ubyte * 16),
                ("segname",         c_ubyte * 16),
                ("addr",            c_uint),
                ("size",            c_uint),
                ("offset",          c_uint),
                ("align",           c_uint),
                ("reloff",          c_uint),
                ("nreloc",          c_uint),
                ("flags",           c_uint),
                ("reserved1",       c_uint),
                ("reserved2",       c_uint),
               ]


class SECTION64_LE(LittleEndianStructure):
    _fields_ = [
                ("sectname",        c_ubyte * 16),
                ("segname",         c_ubyte * 16),
                ("addr",            c_ulonglong),
                ("size",            c_ulonglong),
                ("offset",          c_uint),
                ("align",           c_uint),
                ("reloff",          c_uint),
                ("nreloc",          c_uint),
                ("flags",           c_uint),
                ("reserved1",       c_uint),
                ("reserved2",       c_uint),
               ]

class SECTION64_BE(BigEndianStructure):
    _fields_ = [
                ("sectname",        c_ubyte * 16),
                ("segname",         c_ubyte * 16),
                ("addr",            c_ulonglong),
                ("size",            c_ulonglong),
                ("offset",          c_uint),
                ("align",           c_uint),
                ("reloff",          c_uint),
                ("nreloc",          c_uint),
                ("flags",           c_uint),
                ("reserved1",       c_uint),
                ("reserved2",       c_uint),
               ]


class MACHOFlags(object):
    CPU_TYPE_I386               = 0x7
    CPU_TYPE_X86_64             = (CPU_TYPE_I386 | 0x1000000)
    CPU_TYPE_MIPS               = 0x8
    CPU_TYPE_ARM                = 12
    CPU_TYPE_ARM64              = (CPU_TYPE_ARM | 0x1000000)
    CPU_TYPE_SPARC              = 14
    CPU_TYPE_POWERPC            = 18
    CPU_TYPE_POWERPC64          = (CPU_TYPE_POWERPC | 0x1000000)
    LC_SEGMENT                  = 0x1
    LC_SEGMENT_64               = 0x19
    S_ATTR_SOME_INSTRUCTIONS    = 0x00000400
    S_ATTR_PURE_INSTRUCTIONS    = 0x80000000


class MACHO(object):
    """This class parses the Mach-O."""

    def __init__(self, binary):
        self.__binary = bytearray(binary)

        self.__machHeader   = None
        self.__endianness   = None
        self.__rawLoadCmd   = None
        self.__sections_l   = []

        self.__setEndianness()
        self.__setHeader()
        self.__setLoadCmd()

    def __setEndianness(self):
        magic = self.__binary[0] << 24 | \
                self.__binary[1] << 16 | \
                self.__binary[2] <<  8 | \
                self.__binary[3]
        if magic == 0xfeedface or magic == 0xfeedfacf:
            self.__endianness = CS_MODE_BIG_ENDIAN
        else:
            self.__endianness = 0

    def __setHeader(self):
        if self.__endianness == CS_MODE_BIG_ENDIAN:
            self.__machHeader = MACH_HEADER_BE.from_buffer_copy(self.__binary)
        else:
            self.__machHeader = MACH_HEADER_LE.from_buffer_copy(self.__binary)

        if self.getArchMode() == CS_MODE_32:
            self.__rawLoadCmd   = self.__binary[28:28 + self.__machHeader.sizeofcmds]

        elif self.getArchMode() == CS_MODE_64:
            self.__rawLoadCmd   = self.__binary[32:32 + self.__machHeader.sizeofcmds]

    def __setLoadCmd(self):
        base = self.__rawLoadCmd
        for _ in range(self.__machHeader.ncmds):
            if self.__endianness == CS_MODE_BIG_ENDIAN:
                command = LOAD_COMMAND_BE.from_buffer_copy(base)
            else:
                command = LOAD_COMMAND_LE.from_buffer_copy(base)

            if command.cmd == MACHOFlags.LC_SEGMENT:
                if self.__endianness == CS_MODE_BIG_ENDIAN:
                    segment = SEGMENT_COMMAND_BE.from_buffer_copy(base)
                else:
                    segment = SEGMENT_COMMAND_LE.from_buffer_copy(base)

                self.__setSections(segment, base[56:], 32)

            elif command.cmd == MACHOFlags.LC_SEGMENT_64:
                if self.__endianness == CS_MODE_BIG_ENDIAN:
                    segment = SEGMENT_COMMAND64_BE.from_buffer_copy(base)
                else:
                    segment = SEGMENT_COMMAND64_LE.from_buffer_copy(base)
                self.__setSections(segment, base[72:], 64)

            base = base[command.cmdsize:]

    def __setSections(self, segment, base, sizeHeader):
        for _ in range(segment.nsects):
            if sizeHeader == 32:
                if self.__endianness == CS_MODE_BIG_ENDIAN:
                    section = SECTION_BE.from_buffer_copy(base)
                else:
                    section = SECTION_LE.from_buffer_copy(base)
                section.offset = segment.fileoff + section.addr - segment.vmaddr
                base = base[68:]
                self.__sections_l += [section]
            elif sizeHeader == 64:
                if self.__endianness == CS_MODE_BIG_ENDIAN:
                    section = SECTION64_BE.from_buffer_copy(base)
                else:
                    section = SECTION64_LE.from_buffer_copy(base)
                section.offset = segment.fileoff + section.addr - segment.vmaddr
                base = base[80:]
                self.__sections_l += [section]

    def getEntryPoint(self):
        for section in self.__sections_l:
            if section.sectname[0:6] == "__text":
                return section.addr

    def getExecSections(self):
        ret = []
        for section in self.__sections_l:
            if section.flags & MACHOFlags.S_ATTR_SOME_INSTRUCTIONS or section.flags & MACHOFlags.S_ATTR_PURE_INSTRUCTIONS:
                ret +=  [{
                            "name"    : section.sectname,
                            "offset"  : section.offset,
                            "size"    : section.size,
                            "vaddr"   : section.addr,
                            "opcodes" : bytes(self.__binary[section.offset:section.offset + section.size]),
                        }]
        return ret

    def getDataSections(self):
        ret = []
        for section in self.__sections_l:
            if not section.flags & MACHOFlags.S_ATTR_SOME_INSTRUCTIONS and not section.flags & MACHOFlags.S_ATTR_PURE_INSTRUCTIONS:
                ret +=  [{
                            "name"    : section.sectname,
                            "offset"  : section.offset,
                            "size"    : section.size,
                            "vaddr"   : section.addr,
                            "opcodes" : bytes(self.__binary[section.offset:section.offset + section.size]),
                        }]
        return ret

    def getArch(self):
        if self.__machHeader.cputype == MACHOFlags.CPU_TYPE_I386 or self.__machHeader.cputype == MACHOFlags.CPU_TYPE_X86_64:
            return CS_ARCH_X86
        if self.__machHeader.cputype == MACHOFlags.CPU_TYPE_ARM:
            return CS_ARCH_ARM
        if self.__machHeader.cputype == MACHOFlags.CPU_TYPE_ARM64:
            return CS_ARCH_ARM64
        if self.__machHeader.cputype == MACHOFlags.CPU_TYPE_MIPS:
            return CS_ARCH_MIPS
        if self.__machHeader.cputype == MACHOFlags.CPU_TYPE_POWERPC or self.__machHeader.cputype == MACHOFlags.CPU_TYPE_POWERPC64:
            return CS_ARCH_PPC
        print("[Error] MACHO.getArch() - Architecture not supported")
        return None

    def getArchMode(self):
        if self.__machHeader.magic == 0xfeedface:
            return CS_MODE_32
        elif self.__machHeader.magic == 0xfeedfacf:
            return CS_MODE_64
        print("[Error] MACHO.getArchMode() - Bad Arch size")
        return None

    def getEndian(self):
        if self.__endianness is None:
            print("[Error] MACHO.getEndian() - Unable to determine endianness")
        return self.__endianness

    def getFormat(self):
        return "Mach-O"
