#!/usr/bin/env python2
## -*- coding: utf-8 -*-
##
##  Jonathan Salwan - 2014-04-20 - ROPgadget tool
## 
##  http://twitter.com/JonathanSalwan
##  http://shell-storm.org/project/ROPgadget/
## 
##  This program is free software: you can redistribute it and/or modify
##  it under the terms of the GNU General Public License as published by
##  the Free Software  Foundation, either  version 3 of  the License, or
##  (at your option) any later version.
##
##
##
## Information about ROPgadget
## ===========================
##
## ROPgadget lets you search your gadgets on a binary. It support several 
## file formats and architectures and uses the Capstone disassembler for
## the search engine.
##
##
## Information for future contributors
## ===================================
##
## Classes information
## -------------------
##
##   Args class :     This class is used to parse options. If you want to add a new feature/option,
##                    you have to edit this class.
##
##   PE class:        This class is used to parse all PE format. This class must be return information
##                    like, exec/data section, base image etc. If you want to correct some parsing errors
##                    about PE, you have to edit this class.
##
##   ELF class:       This class is used to parse all ELF. This class must be return information like
##                    exec/data section, entry point etc. If you want to correct some parsing errors about
##                    ELF binary/lib, you have to edit this class.
##
##   MACHO class:     This class is used to parse all Mach-O format. This class must be return information
##                    like exec/data section, entry point etc. If you want to correct some parsing errors
##                    about Mach-O binary, you have to edit this class.
##
##   Binary class:    This class is used like a trampoline/wrapper by Core. The Core doesn't know which
##                    type of binary is loaded (PE/ELF/Mach-O), it just calls wrappers methods. So, 
##                    it's easy to add a new binary format, you just have to add a new class like PE, ELF 
##                    Mach-O. All format classes (PE/ELF/Mach-O/...) must contains these following public 
##                    methods :
##
##                        - getEntryPoint():
##                        - getDataSections():
##                        - getExecSections():
##                        - getArch():
##                        - getArchMode():
##                        - getFormat():
##
##                    Please refers to PE/ELF/Mach-O classes for know how must operate these public methods.
##
##   Gadgets class:   This class is used to generate gadgets on a specific architecture. If you want to manage
##                    the gadgets finding or add a new architecture, you have to edit this class.
##
##   Core class:      This class is the main class, it executes all options and find gadgets. If you want 
##                    to fix some bugs about the gadgets (console / search engine) or if you added a new 
##                    feature you have to edit this class.
##
## Bugs/features
## -------------
##
##   I'm open for all bugs fix and new features. Please report bugs, submit pull requests, etc. on 
##   github at https://github.com/JonathanSalwan/ROPgadget 
##
##
## How can I contribute ?
## ----------------------
##
##   - Add ARM64
##   - Add the ROP chain generation with z3 (Complete the ROPMaker class)
##   - Add system gadgets for MIPS, PPC, Sparc (Gadgets.addSYSGadgets())
##   - Manage big endian in Mach-O format like the ELF classe.
##   - Everything you think is cool :)
##

import argparse
import cmd
import re
import sys

from capstone   import *
from ctypes     import *
from struct     import pack, unpack

MAJOR_VERSION       = 5
MINOR_VERSION       = 1
PYROPGADGET_VERSION = "ROPgadget v%d.%d" %(MAJOR_VERSION, MINOR_VERSION)









# Args class =======================================================================================

class Args:
    def __init__(self):
        self.__args = None
        self.__parse()

    def __parse(self):
        parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                         description="""description:
  ROPgadget lets you search your gadgets on a binary. It supports several 
  file formats and architectures and uses the Capstone disassembler for
  the search engine.

formats supported: 
  - ELF
  - PE
  - Mach-O 

architectures supported:
  - x86
  - x86-64
  - ARM
  - MIPS
  - PowerPC
  - Sparc
""",
                                         epilog="""console commands:
  display              Display all gadgets
  help                 Display the help
  load                 Load all gadgets
  quit                 Quit the console mode
  search               Search specific keywords or not

examples:
  ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 
  ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --payload
  ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --depth 3
  ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --string "main"
  ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --string "m..n"
  ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --opcode c9c3
  ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --only "mov|ret"
  ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --only "mov|pop|xor|ret"
  ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --filter "xchg|add|sub"
  ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --norop --nosys
  ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --range 0x08041000-0x08042000
  ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --string main --range 0x080c9aaa-0x080c9aba
  ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --memstr "/bin/sh"
  ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --console
  ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --badbytes "00|7f|42"
  ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --badbytes "a|b|c|d|e|f"
  ROPgadget.py --binary ./test-suite-binaries/elf-ARMv7-ls --depth 5""")

        parser.add_argument("-v", "--version",  action="store_true",              help="Display the ROPgadget's version")
        parser.add_argument("--binary",         type=str, metavar="<binary>",     help="Specify a binary filename to analyze")
        parser.add_argument("--opcode",         type=str, metavar="<opcodes>",    help="Searh opcode in executable segment")
        parser.add_argument("--string",         type=str, metavar="<string>",     help="Search string in readable segment")
        parser.add_argument("--memstr",         type=str, metavar="<string>",     help="Search each byte in all readable segment")
        parser.add_argument("--depth",          type=int, metavar="<nbyte>",      default=10, help="Depth for search engine (default 10)")
        parser.add_argument("--only",           type=str, metavar="<key>",        help="Only show specific instructions")
        parser.add_argument("--filter",         type=str, metavar="<key>",        help="Suppress specific instructions")
        parser.add_argument("--range",          type=str, metavar="<start-end>",  default="0x0-0x0", help="Search between two addresses (0x...-0x...)")
        parser.add_argument("--badbytes",       type=str, metavar="<byte>",       help="Rejects the specific bytes in gadget's address")
        parser.add_argument("--thumb"  ,        action="store_true",              help="Use the thumb mode for the search engine. (ARM only)")
        parser.add_argument("--console",        action="store_true",              help="Use an interactive console for search engine")
        parser.add_argument("--norop",          action="store_true",              help="Disable ROP search engine")
        parser.add_argument("--nojop",          action="store_true",              help="Disable JOP search engine")
        parser.add_argument("--nosys",          action="store_true",              help="Disable SYS search engine")
        self.__args = parser.parse_args()

        if self.__args.version:
            self.__printVersion()
            sys.exit(0)
        elif self.__args.depth < 2:
            print "[Error] The depth must be >= 2"
            sys.exit(-1)
        elif not self.__args.binary:
            print "[Error] Need a binary filename (--binary or --help)"
            sys.exit(-1)
        elif self.__args.range:
            try:
                rangeS = int(self.__args.range.split('-')[0], 16)
                rangeE = int(self.__args.range.split('-')[1], 16)
            except:
                print "[Error] A range must be set in hexadecimal. Ex: 0x08041000-0x08042000"
                sys.exit(-1)
            if rangeS > rangeE:
                print "[Error] The start value must be greater than end value"
                sys.exit(-1)

    def __printVersion(self):
        print "Version:        %s" %(PYROPGADGET_VERSION)
        print "Author:         Jonathan Salwan" 
        print "Author page:    https://twitter.com/JonathanSalwan" 
        print "Project page:   http://shell-storm.org/project/ROPgadget/" 

    def getArgs(self):
        return self.__args









# PE class =========================================================================================

class PEFlags:
        IMAGE_MACHINE_INTEL_386       = 0x014c
        IMAGE_MACHINE_AMD_8664        = 0x8664
        IMAGE_FILE_MACHINE_ARM        = 0x1c0
        IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b
        IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
        IMAGE_SIZEOF_SHORT_NAME       = 0x8

# tableau (c_char * 32)

class IMAGE_FILE_HEADER(Structure):
    _fields_ =  [
                    ("Magic",                       c_uint),
                    ("Machine",                     c_ushort),
                    ("NumberOfSections",            c_ushort),
                    ("TimeDateStamp",               c_uint),
                    ("PointerToSymbolTable",        c_uint),
                    ("NumberOfSymbols",             c_uint),
                    ("SizeOfOptionalHeader",        c_ushort),
                    ("Characteristics",             c_ushort)
                ]

class IMAGE_OPTIONAL_HEADER(Structure):
    _fields_ =  [
                    ("Magic",                       c_ushort),
                    ("MajorLinkerVersion",          c_ubyte),
                    ("MinorLinkerVersion",          c_ubyte),
                    ("SizeOfCode",                  c_uint),
                    ("SizeOfInitializedData",       c_uint),
                    ("SizeOfUninitializedData",     c_uint),
                    ("AddressOfEntryPoint",         c_uint),
                    ("BaseOfCode",                  c_uint),
                    ("BaseOfData",                  c_uint),
                    ("ImageBase",                   c_uint),
                    ("SectionAlignment",            c_uint),
                    ("FileAlignment",               c_uint),
                    ("MajorOperatingSystemVersion", c_ushort),
                    ("MinorOperatingSystemVersion", c_ushort),
                    ("MajorImageVersion",           c_ushort),
                    ("MinorImageVersion",           c_ushort),
                    ("MajorSubsystemVersion",       c_ushort),
                    ("MinorSubsystemVersion",       c_ushort),
                    ("Win32VersionValue",           c_uint),
                    ("SizeOfImage",                 c_uint),
                    ("SizeOfHeaders",               c_uint),
                    ("CheckSum",                    c_uint),
                    ("Subsystem",                   c_ushort),
                    ("DllCharacteristics",          c_ushort),
                    ("SizeOfStackReserve",          c_uint),
                    ("SizeOfStackCommit",           c_uint),
                    ("SizeOfHeapReserve",           c_uint),
                    ("SizeOfHeapCommit",            c_uint),
                    ("LoaderFlags",                 c_uint),
                    ("NumberOfRvaAndSizes",         c_uint)
                ]

class IMAGE_OPTIONAL_HEADER64(Structure):
    _fields_ =  [
                    ("Magic",                       c_ushort),
                    ("MajorLinkerVersion",          c_ubyte),
                    ("MinorLinkerVersion",          c_ubyte),
                    ("SizeOfCode",                  c_uint),
                    ("SizeOfInitializedData",       c_uint),
                    ("SizeOfUninitializedData",     c_uint),
                    ("AddressOfEntryPoint",         c_uint),
                    ("BaseOfCode",                  c_uint),
                    ("BaseOfData",                  c_uint),
                    ("ImageBase",                   c_ulonglong),
                    ("SectionAlignment",            c_uint),
                    ("FileAlignment",               c_uint),
                    ("MajorOperatingSystemVersion", c_ushort),
                    ("MinorOperatingSystemVersion", c_ushort),
                    ("MajorImageVersion",           c_ushort),
                    ("MinorImageVersion",           c_ushort),
                    ("MajorSubsystemVersion",       c_ushort),
                    ("MinorSubsystemVersion",       c_ushort),
                    ("Win32VersionValue",           c_uint),
                    ("SizeOfImage",                 c_uint),
                    ("SizeOfHeaders",               c_uint),
                    ("CheckSum",                    c_uint),
                    ("Subsystem",                   c_ushort),
                    ("DllCharacteristics",          c_ushort),
                    ("SizeOfStackReserve",          c_ulonglong),
                    ("SizeOfStackCommit",           c_ulonglong),
                    ("SizeOfHeapReserve",           c_ulonglong),
                    ("SizeOfHeapCommit",            c_ulonglong),
                    ("LoaderFlags",                 c_uint),
                    ("NumberOfRvaAndSizes",         c_uint)
                ]

class IMAGE_NT_HEADERS(Structure):
    _fields_ =  [
                    ("Signature",       c_uint),
                    ("FileHeader",      IMAGE_FILE_HEADER),
                    ("OptionalHeader",  IMAGE_OPTIONAL_HEADER)
                ]

class IMAGE_NT_HEADERS64(Structure):
    _fields_ =  [
                    ("Signature",       c_uint),
                    ("FileHeader",      IMAGE_FILE_HEADER),
                    ("OptionalHeader",  IMAGE_OPTIONAL_HEADER64)
                ]

class IMAGE_SECTION_HEADER(Structure):
    _fields_ =  [
                    ("Name",                    c_ubyte * PEFlags.IMAGE_SIZEOF_SHORT_NAME),
                    ("PhysicalAddress",         c_uint),
                    ("VirtualAddress",          c_uint),
                    ("SizeOfRawData",           c_uint),
                    ("PointerToRawData",        c_uint),
                    ("PointerToRelocations",    c_uint),
                    ("PointerToLinenumbers",    c_uint),
                    ("NumberOfRelocations",     c_ushort),
                    ("NumberOfLinenumbers",     c_ushort),
                    ("Characteristics",         c_uint)
                ]

""" This class parses the PE format """
class PE:
    def __init__(self, binary):
        self.__binary = bytearray(binary)

        self.__PEOffset              = 0x00000000
        self.__IMAGE_FILE_HEADER     = None
        self.__IMAGE_OPTIONAL_HEADER = None

        self.__sections_l = []

        self.__getPEOffset()
        self.__parsePEHeader()
        self.__parseOptHeader()
        self.__parseSections()

    def __getPEOffset(self):
        self.__PEOffset = unpack("<I", str(self.__binary[60:64]))[0]
        if self.__binary[self.__PEOffset:self.__PEOffset+4] != "50450000".decode("hex"):
            print "[Error] PE.__getPEOffset() - Bad PE signature"
            sys.exit(-1)
 
    def __parsePEHeader(self):
        PEheader = self.__binary[self.__PEOffset:]
        self.__IMAGE_FILE_HEADER = IMAGE_FILE_HEADER.from_buffer_copy(PEheader)

    def __parseOptHeader(self):
        PEoptHeader = self.__binary[self.__PEOffset+24:self.__PEOffset+24+self.__IMAGE_FILE_HEADER.SizeOfOptionalHeader]

        if unpack("<H", str(PEoptHeader[0:2]))[0] == PEFlags.IMAGE_NT_OPTIONAL_HDR32_MAGIC:
            self.__IMAGE_OPTIONAL_HEADER = IMAGE_OPTIONAL_HEADER.from_buffer_copy(PEoptHeader)

        elif unpack("<H", str(PEoptHeader[0:2]))[0] == PEFlags.IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            self.__IMAGE_OPTIONAL_HEADER = IMAGE_OPTIONAL_HEADER64.from_buffer_copy(PEoptHeader)

        else:
            print "[Error] PE.__parseOptHeader - Bad size header"
            sys.exit(-1)

    def __parseSections(self):
        baseSections = self.__PEOffset+24+self.__IMAGE_FILE_HEADER.SizeOfOptionalHeader
        sizeSections = self.__IMAGE_FILE_HEADER.NumberOfSections * sizeof(IMAGE_SECTION_HEADER)
        base = self.__binary[baseSections:baseSections+sizeSections]

        for i in range(self.__IMAGE_FILE_HEADER.NumberOfSections):
            sec = IMAGE_SECTION_HEADER.from_buffer_copy(base)
            base = base[sizeof(IMAGE_SECTION_HEADER):]
            self.__sections_l += [sec]

        return 0              

    def getEntryPoint(self):
        return self.__IMAGE_OPTIONAL_HEADER.ImageBase + self.__IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint

    def getDataSections(self):
        ret = []
        for section in self.__sections_l:
            if section.Characteristics & 0x80000000:
                ret +=  [{
                            "name"    : section.Name,
                            "offset"  : section.PointerToRawData,
                            "size"    : section.SizeOfRawData,
                            "vaddr"   : section.VirtualAddress + self.__IMAGE_OPTIONAL_HEADER.ImageBase,
                            "opcodes" : str(self.__binary[section.PointerToRawData:section.PointerToRawData+section.SizeOfRawData])
                        }]
        return ret

    def getExecSections(self):
        ret = []
        for section in self.__sections_l:
            if section.Characteristics & 0x20000000:
                ret +=  [{
                            "name"    : section.Name,
                            "offset"  : section.PointerToRawData,
                            "size"    : section.SizeOfRawData,
                            "vaddr"   : section.VirtualAddress + self.__IMAGE_OPTIONAL_HEADER.ImageBase,
                            "opcodes" : str(self.__binary[section.PointerToRawData:section.PointerToRawData+section.SizeOfRawData])
                        }]
        return ret

    def getArch(self):
        if self.__IMAGE_FILE_HEADER.Machine ==  PEFlags.IMAGE_MACHINE_INTEL_386 or self.__IMAGE_FILE_HEADER.Machine == PEFlags.IMAGE_MACHINE_AMD_8664:
            return CS_ARCH_X86
        if self.__IMAGE_FILE_HEADER.Machine == PEFlags.IMAGE_FILE_MACHINE_ARM:
            return CS_ARCH_ARM
        else:
            print "[Error] PE.getArch() - Bad Arch"
            sys.exit(-1)

    def getArchMode(self):
        if self.__IMAGE_OPTIONAL_HEADER.Magic == PEFlags.IMAGE_NT_OPTIONAL_HDR32_MAGIC:
            return CS_MODE_32
        elif self.__IMAGE_OPTIONAL_HEADER.Magic == PEFlags.IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            return CS_MODE_64
        else:
            print "[Error] PE.getArch() - Bad arch size"
            sys.exit(-1)

    def getFormat(self):
        return "PE"









# ELF class ========================================================================================

class ELFFlags:
    ELFCLASS32  = 0x01
    ELFCLASS64  = 0x02
    EI_CLASS    = 0x04
    EI_DATA     = 0x05
    ELFDATA2LSB = 0x01
    ELFDATA2MSB = 0x02
    EM_386      = 0x03
    EM_X86_64   = 0x3e
    EM_ARM      = 0x28
    EM_MIPS     = 0x08
    EM_SPARCv8p = 0x12
    EM_PowerPC  = 0x14

class Elf32_Ehdr_LSB(LittleEndianStructure):
    _fields_ =  [
                    ("e_ident",         c_ubyte * 16),
                    ("e_type",          c_ushort),
                    ("e_machine",       c_ushort),
                    ("e_version",       c_uint),
                    ("e_entry",         c_uint),
                    ("e_phoff",         c_uint),
                    ("e_shoff",         c_uint),
                    ("e_flags",         c_uint),
                    ("e_ehsize",        c_ushort),
                    ("e_phentsize",     c_ushort),
                    ("e_phnum",         c_ushort),
                    ("e_shentsize",     c_ushort),
                    ("e_shnum",         c_ushort),
                    ("e_shstrndx",      c_ushort)
                ]
 
class Elf64_Ehdr_LSB(LittleEndianStructure):
    _fields_ =  [
                    ("e_ident",         c_ubyte * 16),
                    ("e_type",          c_ushort),
                    ("e_machine",       c_ushort),
                    ("e_version",       c_uint),
                    ("e_entry",         c_ulonglong),
                    ("e_phoff",         c_ulonglong),
                    ("e_shoff",         c_ulonglong),
                    ("e_flags",         c_uint),
                    ("e_ehsize",        c_ushort),
                    ("e_phentsize",     c_ushort),
                    ("e_phnum",         c_ushort),
                    ("e_shentsize",     c_ushort),
                    ("e_shnum",         c_ushort),
                    ("e_shstrndx",      c_ushort)
                ]

class Elf32_Phdr_LSB(LittleEndianStructure):
    _fields_ =  [
                    ("p_type",          c_uint),
                    ("p_offset",        c_uint),
                    ("p_vaddr",         c_uint),
                    ("p_paddr",         c_uint),
                    ("p_filesz",        c_uint),
                    ("p_memsz",         c_uint),
                    ("p_flags",         c_uint),
                    ("p_align",         c_uint)
                ]

class Elf64_Phdr_LSB(LittleEndianStructure):
    _fields_ =  [
                    ("p_type",          c_uint),
                    ("p_flags",         c_uint),
                    ("p_offset",        c_ulonglong),
                    ("p_vaddr",         c_ulonglong),
                    ("p_paddr",         c_ulonglong),
                    ("p_filesz",        c_ulonglong),
                    ("p_memsz",         c_ulonglong),
                    ("p_align",         c_ulonglong)
                ]

class Elf32_Shdr_LSB(LittleEndianStructure):
    _fields_ =  [
                    ("sh_name",         c_uint),
                    ("sh_type",         c_uint),
                    ("sh_flags",        c_uint),
                    ("sh_addr",         c_uint),
                    ("sh_offset",       c_uint),
                    ("sh_size",         c_uint),
                    ("sh_link",         c_uint),
                    ("sh_info",         c_uint),
                    ("sh_addralign",    c_uint),
                    ("sh_entsize",      c_uint)
                ]

class Elf64_Shdr_LSB(LittleEndianStructure):
    _fields_ =  [
                    ("sh_name",         c_uint),
                    ("sh_type",         c_uint),
                    ("sh_flags",        c_ulonglong),
                    ("sh_addr",         c_ulonglong),
                    ("sh_offset",       c_ulonglong),
                    ("sh_size",         c_ulonglong),
                    ("sh_link",         c_uint),
                    ("sh_info",         c_uint),
                    ("sh_addralign",    c_ulonglong),
                    ("sh_entsize",      c_ulonglong)
                ]

class Elf32_Ehdr_MSB(BigEndianStructure):
    _fields_ =  [
                    ("e_ident",         c_ubyte * 16),
                    ("e_type",          c_ushort),
                    ("e_machine",       c_ushort),
                    ("e_version",       c_uint),
                    ("e_entry",         c_uint),
                    ("e_phoff",         c_uint),
                    ("e_shoff",         c_uint),
                    ("e_flags",         c_uint),
                    ("e_ehsize",        c_ushort),
                    ("e_phentsize",     c_ushort),
                    ("e_phnum",         c_ushort),
                    ("e_shentsize",     c_ushort),
                    ("e_shnum",         c_ushort),
                    ("e_shstrndx",      c_ushort)
                ]
 
class Elf64_Ehdr_MSB(BigEndianStructure):
    _fields_ =  [
                    ("e_ident",         c_ubyte * 16),
                    ("e_type",          c_ushort),
                    ("e_machine",       c_ushort),
                    ("e_version",       c_uint),
                    ("e_entry",         c_ulonglong),
                    ("e_phoff",         c_ulonglong),
                    ("e_shoff",         c_ulonglong),
                    ("e_flags",         c_uint),
                    ("e_ehsize",        c_ushort),
                    ("e_phentsize",     c_ushort),
                    ("e_phnum",         c_ushort),
                    ("e_shentsize",     c_ushort),
                    ("e_shnum",         c_ushort),
                    ("e_shstrndx",      c_ushort)
                ]

class Elf32_Phdr_MSB(BigEndianStructure):
    _fields_ =  [
                    ("p_type",          c_uint),
                    ("p_offset",        c_uint),
                    ("p_vaddr",         c_uint),
                    ("p_paddr",         c_uint),
                    ("p_filesz",        c_uint),
                    ("p_memsz",         c_uint),
                    ("p_flags",         c_uint),
                    ("p_align",         c_uint)
                ]

class Elf64_Phdr_MSB(BigEndianStructure):
    _fields_ =  [
                    ("p_type",          c_uint),
                    ("p_flags",         c_uint),
                    ("p_offset",        c_ulonglong),
                    ("p_vaddr",         c_ulonglong),
                    ("p_paddr",         c_ulonglong),
                    ("p_filesz",        c_ulonglong),
                    ("p_memsz",         c_ulonglong),
                    ("p_align",         c_ulonglong)
                ]

class Elf32_Shdr_MSB(BigEndianStructure):
    _fields_ =  [
                    ("sh_name",         c_uint),
                    ("sh_type",         c_uint),
                    ("sh_flags",        c_uint),
                    ("sh_addr",         c_uint),
                    ("sh_offset",       c_uint),
                    ("sh_size",         c_uint),
                    ("sh_link",         c_uint),
                    ("sh_info",         c_uint),
                    ("sh_addralign",    c_uint),
                    ("sh_entsize",      c_uint)
                ]

class Elf64_Shdr_MSB(BigEndianStructure):
    _fields_ =  [
                    ("sh_name",         c_uint),
                    ("sh_type",         c_uint),
                    ("sh_flags",        c_ulonglong),
                    ("sh_addr",         c_ulonglong),
                    ("sh_offset",       c_ulonglong),
                    ("sh_size",         c_ulonglong),
                    ("sh_link",         c_uint),
                    ("sh_info",         c_uint),
                    ("sh_addralign",    c_ulonglong),
                    ("sh_entsize",      c_ulonglong)
                ]

""" This class parses the ELF """
class ELF:
    def __init__(self, binary):
        self.__binary    = bytearray(binary)
        self.__ElfHeader = None
        self.__shdr_l    = []
        self.__phdr_l    = []

        self.__setHeaderElf()
        self.__setShdr()
        self.__setPhdr()

    """ Parse ELF header """
    def __setHeaderElf(self):
        e_ident = str(self.__binary[:15])

        ei_class = unpack("<B", e_ident[ELFFlags.EI_CLASS])[0]
        ei_data  = unpack("<B", e_ident[ELFFlags.EI_DATA])[0]

        if ei_class != ELFFlags.ELFCLASS32 and ei_class != ELFFlags.ELFCLASS64:
            print "[Error] ELF.__setHeaderElf() - Bad Arch size"
            sys.exit(-1)

        if ei_data != ELFFlags.ELFDATA2LSB and ei_data != ELFFlags.ELFDATA2MSB:
            print "[Error] ELF.__setHeaderElf() - Bad architecture endian"
            sys.exit(-1)

        if ei_class == ELFFlags.ELFCLASS32: 
            if   ei_data == ELFFlags.ELFDATA2LSB: self.__ElfHeader = Elf32_Ehdr_LSB.from_buffer_copy(self.__binary)
            elif ei_data == ELFFlags.ELFDATA2MSB: self.__ElfHeader = Elf32_Ehdr_MSB.from_buffer_copy(self.__binary)
        elif ei_class == ELFFlags.ELFCLASS64: 
            if   ei_data == ELFFlags.ELFDATA2LSB: self.__ElfHeader = Elf64_Ehdr_LSB.from_buffer_copy(self.__binary)
            elif ei_data == ELFFlags.ELFDATA2MSB: self.__ElfHeader = Elf64_Ehdr_MSB.from_buffer_copy(self.__binary)

        self.getArch() # Check if architecture is supported

    """ Parse Section header """
    def __setShdr(self):
        shdr_num = self.__ElfHeader.e_shnum
        base = self.__binary[self.__ElfHeader.e_shoff:]
        shdr_l = []

        e_ident = str(self.__binary[:15])
        ei_data = unpack("<B", e_ident[ELFFlags.EI_DATA])[0]

        for i in range(shdr_num):

            if self.getArchMode() == CS_MODE_32:
                if   ei_data == ELFFlags.ELFDATA2LSB: shdr = Elf32_Shdr_LSB.from_buffer_copy(base)
                elif ei_data == ELFFlags.ELFDATA2MSB: shdr = Elf32_Shdr_MSB.from_buffer_copy(base)
            elif self.getArchMode() == CS_MODE_64:
                if   ei_data == ELFFlags.ELFDATA2LSB: shdr = Elf64_Shdr_LSB.from_buffer_copy(base)
                elif ei_data == ELFFlags.ELFDATA2MSB: shdr = Elf64_Shdr_MSB.from_buffer_copy(base)

            self.__shdr_l.append(shdr)
            base = base[self.__ElfHeader.e_shentsize:]

        # setup name from the strings table
        string_table = str(self.__binary[(self.__shdr_l[self.__ElfHeader.e_shstrndx].sh_offset):])
        for i in range(shdr_num):
            self.__shdr_l[i].str_name = string_table[self.__shdr_l[i].sh_name:].split('\0')[0]

    """ Parse Program header """
    def __setPhdr(self):
        pdhr_num = self.__ElfHeader.e_phnum
        base = self.__binary[self.__ElfHeader.e_phoff:]
        phdr_l = []

        e_ident = str(self.__binary[:15])
        ei_data = unpack("<B", e_ident[ELFFlags.EI_DATA])[0]

        for i in range(pdhr_num):
            if self.getArchMode() == CS_MODE_32:
                if   ei_data == ELFFlags.ELFDATA2LSB: phdr = Elf32_Phdr_LSB.from_buffer_copy(base)
                elif ei_data == ELFFlags.ELFDATA2MSB: phdr = Elf32_Phdr_MSB.from_buffer_copy(base)
            elif self.getArchMode() == CS_MODE_64:
                if   ei_data == ELFFlags.ELFDATA2LSB: phdr = Elf64_Phdr_LSB.from_buffer_copy(base)
                elif ei_data == ELFFlags.ELFDATA2MSB: phdr = Elf64_Phdr_MSB.from_buffer_copy(base)

            self.__phdr_l.append(phdr)
            base = base[self.__ElfHeader.e_phentsize:]

    def getEntryPoint(self):
        return self.__e_entry

    def getExecSections(self):
        ret = []
        for section in self.__shdr_l:
            if section.sh_flags & 0x4:
                ret +=  [{
                            "name"    : section.str_name,
                            "offset"  : section.sh_offset,
                            "size"    : section.sh_size,
                            "vaddr"   : section.sh_addr,
                            "opcodes" : str(self.__binary[section.sh_offset:section.sh_offset+section.sh_size])
                        }]
        return ret

    def getDataSections(self):
        ret = []
        for section in self.__shdr_l:
            if not (section.sh_flags & 0x4) and (section.sh_flags & 0x2):
                ret +=  [{
                            "name"    : section.str_name,
                            "offset"  : section.sh_offset,
                            "size"    : section.sh_size,
                            "vaddr"   : section.sh_addr,
                            "opcodes" : str(self.__binary[section.sh_offset:section.sh_offset+section.sh_size])
                        }]
        return ret

    def getArch(self):
        if self.__ElfHeader.e_machine == ELFFlags.EM_386 or self.__ElfHeader.e_machine == ELFFlags.EM_X86_64: 
            return CS_ARCH_X86
        elif self.__ElfHeader.e_machine == ELFFlags.EM_ARM:
            return CS_ARCH_ARM
        elif self.__ElfHeader.e_machine == ELFFlags.EM_MIPS:
            return CS_ARCH_MIPS
        elif self.__ElfHeader.e_machine == ELFFlags.EM_PowerPC:
            return CS_ARCH_PPC
        elif self.__ElfHeader.e_machine == ELFFlags.EM_SPARCv8p:
            return CS_ARCH_SPARC
        else:
            print "[Error] ELF.getArch() - Architecture not supported"
            sys.exit(-1)
            
    def getArchMode(self):
        if self.__ElfHeader.e_ident[ELFFlags.EI_CLASS] == ELFFlags.ELFCLASS32: 
            return CS_MODE_32
        elif self.__ElfHeader.e_ident[ELFFlags.EI_CLASS] == ELFFlags.ELFCLASS64: 
            return CS_MODE_64
        else:
            print "[Error] ELF.getArchMode() - Bad Arch size"
            sys.exit(-1)

    def getFormat(self):
        return "ELF"









# Mach-O class ========================================================================================

class MACH_HEADER(Structure):
    _fields_ = [
                ("magic",           c_uint),
                ("cputype",         c_uint),
                ("cpusubtype",      c_uint),
                ("filetype",        c_uint),
                ("ncmds",           c_uint),
                ("sizeofcmds",      c_uint),
                ("flags",           c_uint)
               ]

class LOAD_COMMAND(Structure):
    _fields_ = [
                ("cmd",             c_uint),
                ("cmdsize",         c_uint)
               ]

class SEGMENT_COMMAND(Structure):
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
                ("flags",           c_uint)
               ]

class SEGMENT_COMMAND64(Structure):
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
                ("flags",           c_uint)
               ]

class SECTION(Structure):
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
                ("reserved2",       c_uint)  
               ]
    
class SECTION64(Structure):
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
                ("reserved2",       c_uint)  
               ]

class MACHOFlags:
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

""" This class parses the Mach-O """
class MACHO:
    def __init__(self, binary):
        self.__binary = bytearray(binary)

        self.__machHeader   = None
        self.__rawLoadCmd   = None
        self.__sections_l   = []

        self.__setHeader()
        self.__setLoadCmd()

    def __setHeader(self):
        self.__machHeader = MACH_HEADER.from_buffer_copy(self.__binary)

        if self.getArchMode() == CS_MODE_32:
            self.__rawLoadCmd   = self.__binary[28:28+self.__machHeader.sizeofcmds]

        elif self.getArchMode() == CS_MODE_64:
            self.__rawLoadCmd   = self.__binary[32:32+self.__machHeader.sizeofcmds]

    def __setLoadCmd(self):
        base = self.__rawLoadCmd
        for i in range(self.__machHeader.ncmds):
            command = LOAD_COMMAND.from_buffer_copy(base)

            if command.cmd == MACHOFlags.LC_SEGMENT:
                segment = SEGMENT_COMMAND.from_buffer_copy(base)
                self.__setSections(segment.nsects, base[56:], 32)

            elif command.cmd == MACHOFlags.LC_SEGMENT_64:
                segment = SEGMENT_COMMAND64.from_buffer_copy(base)
                self.__setSections(segment.nsects, base[72:], 64)

            base = base[command.cmdsize:]

    def __setSections(self, sectionsNumber, base, sizeHeader):
        for i in range(sectionsNumber):
            if sizeHeader == 32:
                section = SECTION.from_buffer_copy(base)
                base = base[68:]
                self.__sections_l += [section]
            elif sizeHeader == 64:
                section = SECTION64.from_buffer_copy(base)
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
                            "opcodes" : str(self.__binary[section.offset:section.offset+section.size])
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
                            "opcodes" : str(self.__binary[section.offset:section.offset+section.size])
                        }]
        return ret

    def getArch(self):
        if self.__machHeader.cputype == MACHOFlags.CPU_TYPE_I386 or self.__machHeader.cputype == MACHOFlags.CPU_TYPE_X86_64: 
            return CS_ARCH_X86
        if self.__machHeader.cputype == MACHOFlags.CPU_TYPE_ARM:
            return CS_ARCH_ARM
        if self.__machHeader.cputype == MACHOFlags.CPU_TYPE_MIPS:
            return CS_ARCH_MIPS
        else:
            print "[Error] MACHO.getArch() - Architecture not supported"
            sys.exit(-1)
            
    def getArchMode(self):
        if self.__machHeader.magic == 0xfeedface: 
            return CS_MODE_32
        elif self.__machHeader.magic == 0xfeedfacf:
            return CS_MODE_64
        else:
            print "[Error] MACHO.getArchMode() - Bad Arch size"
            sys.exit(-1)
        pass

    def getFormat(self):
        return "Mach-O"









# Binary class =====================================================================================

""" This class is a wrapper for a Format Object """
class Binary:
    def __init__(self, fileName):
        self.__fileName  = fileName
        self.__rawBinary = None
        self.__binary    = None
        
        try:
            fd = open(fileName, "r")
            self.__rawBinary = fd.read()
            fd.close()
        except:
            print "[Error] Can't open the binary or binary not found"
            sys.exit(-1)

        if   self.__rawBinary[:4] == "7f454c46".decode("hex"):
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









# Gadgets class ====================================================================================

class Gadgets:
    def __init__(self, binary, options):
        self.__binary  = binary
        self.__options = options

    def __checkInstructionBlackListedX86(self, insts):
        bl = ["db", "int3"]
        for inst in insts:
            for b in bl:
                if inst.split(" ")[0] == b:
                    return True 
        return False

    def __passCleanX86(self, gadgets):
        new = []
        br = ["ret", "int", "sysenter", "jmp", "call"]
        for gadget in gadgets:
            insts = gadget["gadget"].split(" ; ")
            if len(insts) == 1 and insts[0].split(" ")[0] not in br:
                continue
            if insts[-1].split(" ")[0] not in br:
                continue
            if self.__checkInstructionBlackListedX86(insts):
                continue
            new += [gadget]
        return new

    def __gadgetsFinding(self, section, gadgets):

        C_OP    = 0
        C_SIZE  = 1
        C_ALIGN = 2
        C_ARCH  = 3
        C_MODE  = 4

        ret = []
        for gad in gadgets:
            allRefRet = [m.start() for m in re.finditer(gad[C_OP], section["opcodes"])]
            for ref in allRefRet:
                for i in range(self.__options.depth):
                    md = Cs(gad[C_ARCH], gad[C_MODE])
                    decodes = md.disasm(section["opcodes"][ref-(i*gad[C_ALIGN]):ref+gad[C_SIZE]], section["vaddr"]+ref)
                    gadget = ""
                    for decode in decodes:
                        gadget += (decode.mnemonic + " " + decode.op_str + " ; ").replace("  ", " ")
                    gadget = gadget[:-3]
                    ret += [{"vaddr" :  section["vaddr"]+ref-i, "gadget" : gadget}]
        return ret

    def addROPGadgets(self, section):

        gadgetsX86   = [
                            ["\xc3", 1, 1, self.__binary.getArch(), self.__binary.getArchMode()]     # ret
                       ]
        gadgetsSparc = [
                            ["\x81\xc3\xe0\x08", 4, 4, self.__binary.getArch(), CS_MODE_BIG_ENDIAN], # retl
                            ["\x81\xc7\xe0\x08", 4, 4, self.__binary.getArch(), CS_MODE_BIG_ENDIAN], # ret
                            ["\x81\xe8\x00\x00", 4, 4, self.__binary.getArch(), CS_MODE_BIG_ENDIAN]  # restore
                       ]
        gadgetsPPC   = [
                            ["\x4e\x80\x00\x20", 4, 4, self.__binary.getArch(), self.__binary.getArchMode() + CS_MODE_BIG_ENDIAN] # blr
                       ]

        if   self.__binary.getArch() == CS_ARCH_X86:    gadgets = gadgetsX86
        elif self.__binary.getArch() == CS_ARCH_MIPS:   gadgets = []            # MIPS doesn't contains RET instruction set. Only JOP gadgets
        elif self.__binary.getArch() == CS_ARCH_PPC:    gadgets = gadgetsPPC
        elif self.__binary.getArch() == CS_ARCH_SPARC:  gadgets = gadgetsSparc
        elif self.__binary.getArch() == CS_ARCH_ARM:    gadgets = []            # ARM doesn't contains RET instruction set. Only JOP gadgets
        else:
            print "Gadgets().addROPGadgets() - Architecture not supported"
            sys.exit(-1)

        return self.__gadgetsFinding(section, gadgets)

    def addJOPGadgets(self, section):

        gadgetsX86      = [
                               ["\xff[\x20\x21\x22\x23\x26\x27]{1}", 2, 1, self.__binary.getArch(), self.__binary.getArchMode()], # jmp  [reg]
                               ["\xff[\xe0\xe1\xe2\xe3\xe6\xe7]{1}", 2, 1, self.__binary.getArch(), self.__binary.getArchMode()], # jmp  [reg]
                               ["\xff[\x10\x11\x12\x13\x16\x17]{1}", 2, 1, self.__binary.getArch(), self.__binary.getArchMode()], # jmp  [reg]
                               ["\xff[\xd0\xd1\xd2\xd3\xd6\xd7]{1}", 2, 1, self.__binary.getArch(), self.__binary.getArchMode()]  # jmp  [reg]
                          ]
        gadgetsSparc    = [
                               ["\x81\xc0[\x00\x40\x80\xc0]{1}\x00", 4, 4, self.__binary.getArch(), CS_MODE_BIG_ENDIAN]  # jmp %g[0-3]
                          ]
        gadgetsMIPS     = [
                               ["\x09\xf8\x20\x03", 4, 4, self.__binary.getArch(), self.__binary.getArchMode()], # jrl $t9
                               ["\x08\x00\x20\x03", 4, 4, self.__binary.getArch(), self.__binary.getArchMode()], # jr  $t9
                               ["\x08\x00\xe0\x03", 4, 4, self.__binary.getArch(), self.__binary.getArchMode()]  # jr  $ra
                          ]
        gadgetsARMThumb = [
                                ["[\x00\x08\x10\x18\x20\x28\x30\x38\x40\x48\x70]{1}\x47", 2, 2, self.__binary.getArch(), CS_MODE_THUMB], # bx   reg
                                ["[\x80\x88\x90\x98\xa0\xa8\xb0\xb8\xc0\xc8\xf0]{1}\x47", 2, 2, self.__binary.getArch(), CS_MODE_THUMB], # blx  reg
                                ["[\x00-\xff]{1}\xbd", 2, 2, self.__binary.getArch(), CS_MODE_THUMB]                                     # pop {,pc}
                          ]
        gadgetsARM      = [
                                ["[\x10-\x19\x1e]{1}\xff\x2f\xe1", 4, 4, self.__binary.getArch(), CS_MODE_ARM],  # bx   reg
                                ["[\x30-\x39\x3e]{1}\xff\x2f\xe1", 4, 4, self.__binary.getArch(), CS_MODE_ARM],  # blx  reg
                                ["[\x00-\xff]{1}\x80\xbd\xe8", 4, 4, self.__binary.getArch(), CS_MODE_ARM]       # pop {,pc}
                          ]

        if   self.__binary.getArch() == CS_ARCH_X86:    gadgets = gadgetsX86
        elif self.__binary.getArch() == CS_ARCH_MIPS:   gadgets = gadgetsMIPS
        elif self.__binary.getArch() == CS_ARCH_PPC:    gadgets = [] # PPC architecture doesn't contains reg branch instruction
        elif self.__binary.getArch() == CS_ARCH_SPARC:  gadgets = gadgetsSparc
        elif self.__binary.getArch() == CS_ARCH_ARM:
            if self.__options.thumb:    
                gadgets = gadgetsARMThumb
            else:
                gadgets = gadgetsARM
        else:
            print "Gadgets().addJOPGadgets() - Architecture not supported"
            sys.exit(-1)

        return self.__gadgetsFinding(section, gadgets)

    def addSYSGadgets(self, section):

        gadgetsX86      = [
                               ["\xcd\x80", 2, 1, self.__binary.getArch(), self.__binary.getArchMode()], # int 0x80
                               ["\x0f\x34", 2, 1, self.__binary.getArch(), self.__binary.getArchMode()], # sysenter
                          ]
        gadgetsARMThumb = [
                                ["\x00-\xff]{1}\xef", 2, 2, self.__binary.getArch(), CS_MODE_THUMB], # svc
                          ]
        gadgetsARM      = [
                                ["\x00-\xff]{3}\xef", 4, 4, self.__binary.getArch(), CS_MODE_ARM] # svc
                          ]

        if   self.__binary.getArch() == CS_ARCH_X86:    gadgets = gadgetsX86
        elif self.__binary.getArch() == CS_ARCH_MIPS:   gadgets = [] # TODO
        elif self.__binary.getArch() == CS_ARCH_PPC:    gadgets = [] # TODO
        elif self.__binary.getArch() == CS_ARCH_SPARC:  gadgets = [] # TODO
        elif self.__binary.getArch() == CS_ARCH_ARM:
            if self.__options.thumb:    
                gadgets = gadgetsARMThumb
            else:
                gadgets = gadgetsARM
        else:
            print "Gadgets().addJOPGadgets() - Architecture not supported"
            sys.exit(-1)

        return self.__gadgetsFinding(section, gadgets)

    def passClean(self, gadgets):
        if   self.__binary.getArch() == CS_ARCH_X86:    return self.__passCleanX86(gadgets)
        elif self.__binary.getArch() == CS_ARCH_MIPS:   return gadgets 
        elif self.__binary.getArch() == CS_ARCH_PPC:    return gadgets
        elif self.__binary.getArch() == CS_ARCH_SPARC:  return gadgets
        elif self.__binary.getArch() == CS_ARCH_ARM:    return gadgets 
        else:
            print "Gadgets().passClean() - Architecture not supported"
            sys.exit(-1)









# ROPMaker class ===================================================================================

class ROPMaker:
    def __init__(self, gadgets):
        self.__gadgets = gadgets

    def gen(self):
        print "[Error] ROPchain not implemented yet"
        pass









# Core class =======================================================================================

""" The main class """
class Core(cmd.Cmd):
    def __init__(self, options):
        cmd.Cmd.__init__(self)
        self.__options = options
        self.__binary  = Binary(options.binary)
        self.__gadgets = []
        self.prompt    = '(ROPgadget)> '

    def __deleteDuplicate(self):
        new, insts = [], []
        for gadget in self.__gadgets:
            gad = gadget["gadget"]
            if gad in insts:
                continue
            insts += [gad]
            new += [gadget]
        self.__gadgets = new

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

    def __deleteBadBytes(self):
        if not self.__options.badbytes:
            return
        new = []
        bbytes = self.__options.badbytes.split("|")
        archMode = self.__binary.getArchMode()
        for gadget in self.__gadgets:
            gadAddr = ("%08x" %(gadget["vaddr"]) if archMode == CS_MODE_32 else "%016x" %(gadget["vaddr"]))
            try:
                for x in bbytes:
                    if x in gadAddr: raise
                new += [gadget]
            except:
                pass
        self.__gadgets = new

    def __getAllgadgets(self):
        G = Gadgets(self.__binary, self.__options)
        execSections = self.__binary.getExecSections()

        # Find ROP/JOP/SYS gadgets
        for section in execSections:
            if not self.__options.norop: self.__gadgets += G.addROPGadgets(section)
            if not self.__options.nojop: self.__gadgets += G.addJOPGadgets(section)
            if not self.__options.nosys: self.__gadgets += G.addSYSGadgets(section)

        # Pass clean single instruction and unknown instructions
        self.__gadgets = G.passClean(self.__gadgets)

        # Badbytes option
        self.__deleteBadBytes()

        # Delete duplicate
        self.__deleteDuplicate()

        # Sorted alphabetically
        self.__gadgets = sorted(self.__gadgets, key=lambda key : key["gadget"])

        # Applicate filters
        self.__onlyOption()
        self.__filterOption()
        self.__rangeOption()

    def __lookingForGadgets(self):
        arch = self.__binary.getArchMode()
        print "Gadgets information\n============================================================"
        for gadget in self.__gadgets:
            vaddr = gadget["vaddr"]
            insts = gadget["gadget"]
            print ("0x%08x" %(vaddr) if arch == CS_MODE_32 else "0x%016x" %(vaddr)) + " : %s" %(insts)
        print "\nUnique gadgets found: %d" %(len(self.__gadgets))

    def __lookingForAString(self, string):
        dataSections = self.__binary.getDataSections()
        arch = self.__binary.getArchMode()
        print "Strings information\n============================================================"
        for section in dataSections:
            allRef = [m.start() for m in re.finditer(string, section["opcodes"])]
            for ref in allRef:
                vaddr = section["vaddr"]+ref
                string = section["opcodes"][ref:ref+len(string)]
                rangeS = int(self.__options.range.split('-')[0], 16)
                rangeE = int(self.__options.range.split('-')[1], 16)
                if (rangeS == 0 and rangeE == 0) or (vaddr >= rangeS and vaddr <= rangeE):
                    print ("0x%08x" %(vaddr) if arch == CS_MODE_32 else "0x%016x" %(vaddr)) + " : %s" %(string)

    def __lookingForOpcodes(self, opcodes):
        execSections = self.__binary.getExecSections()
        arch = self.__binary.getArchMode()
        print "Opcodes information\n============================================================"
        for section in execSections:
            allRef = [m.start() for m in re.finditer(opcodes.decode("hex"), section["opcodes"])]
            for ref in allRef:
                vaddr = section["vaddr"]+ref
                rangeS = int(self.__options.range.split('-')[0], 16)
                rangeE = int(self.__options.range.split('-')[1], 16)
                if (rangeS == 0 and rangeE == 0) or (vaddr >= rangeS and vaddr <= rangeE):
                    print ("0x%08x" %(vaddr) if arch == CS_MODE_32 else "0x%016x" %(vaddr)) + " : %s" %(opcodes)

    def __lookingForMemStr(self, memstr):
        sections  = self.__binary.getExecSections()
        sections += self.__binary.getDataSections()
        arch = self.__binary.getArchMode()
        print "Memory bytes information\n======================================================="
        chars = list(memstr)
        for char in chars:
            try:
                for section in sections:
                    allRef = [m.start() for m in re.finditer(char, section["opcodes"])]
                    for ref in allRef:
                        vaddr = section["vaddr"]+ref
                        rangeS = int(self.__options.range.split('-')[0], 16)
                        rangeE = int(self.__options.range.split('-')[1], 16)
                        if (rangeS == 0 and rangeE == 0) or (vaddr >= rangeS and vaddr <= rangeE):
                            print ("0x%08x" %(vaddr) if arch == CS_MODE_32 else "0x%016x" %(vaddr)) + " : '%c'" %(char)
                            raise
            except:
                pass

    def analyze(self):
        if   self.__options.string:   self.__lookingForAString(self.__options.string)
        elif self.__options.opcode:   self.__lookingForOpcodes(self.__options.opcode)
        elif self.__options.memstr:   self.__lookingForMemStr(self.__options.memstr)
        elif self.__options.console:  self.cmdloop()
        else: 
            self.__getAllgadgets()
            self.__lookingForGadgets()

    # Console methods  ============================================

    def do_quit(self, s):
        return True

    def help_quit(self):
        print "Syntax: quit -- Terminates the application"

    def do_load(self, s):
        print "[+] Loading gadgets, please wait..."
        self.__getAllgadgets()
        print "[+] Gadgets loaded !"
        
    def help_load(self):
        print "Syntax: load -- Load all gadgets"

    def do_display(self, s):
        self.__lookingForGadgets()

    def help_display(self):
        print "Syntax: display -- Display all gadgets loaded"

    def __withK(self, listK, gadget):
        if len(listK) == 0:
            return True
        for a in listK:
            if a not in gadget:
                return False
        return True
        
    def __withoutK(self, listK, gadget):
        for a in listK:
            if a in gadget:
                return False
        return True

    def do_search(self, s):
        args = s.split()
        if not len(args):
            return self.help_search()
        if not len(self.__gadgets):
            print "[-] You have to load gadgets before (help load)"
            return
        withK, withoutK = [], []
        for a in args:
            if a[0:1] == "!":
                withoutK += [a[1:]]
            else:
                withK += [a]
        arch = self.__binary.getArchMode()
        for gadget in self.__gadgets:
            vaddr = gadget["vaddr"]
            insts = gadget["gadget"]
            if self.__withK(withK, insts) and self.__withoutK(withoutK, insts):
                print ("0x%08x" %(vaddr) if arch == CS_MODE_32 else "0x%016x" %(vaddr)) + " : %s" %(insts)

    def help_search(self):
        print "Syntax: search <keyword1 keyword2 keyword3...> -- Filter with or without keywords"
        print "keyword  = with"
        print "!keyword = witout"
        








# Main =============================================================================================

if __name__ == "__main__":
    Core(Args().getArgs()).analyze()
    sys.exit(0)

