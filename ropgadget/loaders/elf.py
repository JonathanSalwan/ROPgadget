## -*- coding: utf-8 -*-
##
##  Jonathan Salwan - 2014-05-12 - ROPgadget tool
##
##  http://twitter.com/JonathanSalwan
##  http://shell-storm.org/project/ROPgadget/
##

from ctypes import *

from capstone import *


class ELFFlags(object):
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
    EM_ARM64    = 0xb7


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
                    ("e_shstrndx",      c_ushort),
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
                    ("e_shstrndx",      c_ushort),
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
                    ("p_align",         c_uint),
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
                    ("p_align",         c_ulonglong),
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
                    ("sh_entsize",      c_uint),
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
                    ("sh_entsize",      c_ulonglong),
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
                    ("e_shstrndx",      c_ushort),
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
                    ("e_shstrndx",      c_ushort),
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
                    ("p_align",         c_uint),
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
                    ("p_align",         c_ulonglong),
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
                    ("sh_entsize",      c_uint),
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
                    ("sh_entsize",      c_ulonglong),
                ]


class ELF(object):
    """This class parses the ELF."""

    def __init__(self, binary):
        self.__binary    = bytearray(binary)
        self.__ElfHeader = None
        self.__shdr_l    = []
        self.__phdr_l    = []

        self.__setHeaderElf()
        self.__setShdr()
        self.__setPhdr()

    def __setHeaderElf(self):
        """Parse ELF header."""
        e_ident = self.__binary[:15]

        ei_class = e_ident[ELFFlags.EI_CLASS]
        ei_data  = e_ident[ELFFlags.EI_DATA]

        if ei_class != ELFFlags.ELFCLASS32 and ei_class != ELFFlags.ELFCLASS64:
            print("[Error] ELF.__setHeaderElf() - Bad Arch size")
            return None

        if ei_data != ELFFlags.ELFDATA2LSB and ei_data != ELFFlags.ELFDATA2MSB:
            print("[Error] ELF.__setHeaderElf() - Bad architecture endian")
            return None

        if ei_class == ELFFlags.ELFCLASS32:
            if   ei_data == ELFFlags.ELFDATA2LSB: self.__ElfHeader = Elf32_Ehdr_LSB.from_buffer_copy(self.__binary)
            elif ei_data == ELFFlags.ELFDATA2MSB: self.__ElfHeader = Elf32_Ehdr_MSB.from_buffer_copy(self.__binary)
        elif ei_class == ELFFlags.ELFCLASS64:
            if   ei_data == ELFFlags.ELFDATA2LSB: self.__ElfHeader = Elf64_Ehdr_LSB.from_buffer_copy(self.__binary)
            elif ei_data == ELFFlags.ELFDATA2MSB: self.__ElfHeader = Elf64_Ehdr_MSB.from_buffer_copy(self.__binary)

        self.getArch()  # Check if architecture is supported

    def __setShdr(self):
        """Parse Section header."""
        shdr_num = self.__ElfHeader.e_shnum
        base = self.__binary[self.__ElfHeader.e_shoff:]
        self.__shdr_l = []

        e_ident = self.__binary[:15]
        ei_data = e_ident[ELFFlags.EI_DATA]

        for _ in range(shdr_num):
            if self.getArchMode() == CS_MODE_32:
                if   ei_data == ELFFlags.ELFDATA2LSB: shdr = Elf32_Shdr_LSB.from_buffer_copy(base)
                elif ei_data == ELFFlags.ELFDATA2MSB: shdr = Elf32_Shdr_MSB.from_buffer_copy(base)
            elif self.getArchMode() == CS_MODE_64:
                if   ei_data == ELFFlags.ELFDATA2LSB: shdr = Elf64_Shdr_LSB.from_buffer_copy(base)
                elif ei_data == ELFFlags.ELFDATA2MSB: shdr = Elf64_Shdr_MSB.from_buffer_copy(base)

            self.__shdr_l.append(shdr)
            base = base[self.__ElfHeader.e_shentsize:]

        # setup name from the strings table
        if self.__ElfHeader.e_shstrndx != 0:
            string_table = bytes(self.__binary[(self.__shdr_l[self.__ElfHeader.e_shstrndx].sh_offset):])
            for i in range(shdr_num):
                self.__shdr_l[i].str_name = string_table[self.__shdr_l[i].sh_name:].split(b'\x00')[0].decode('utf8')

    def __setPhdr(self):
        """Parse Program header."""
        pdhr_num = self.__ElfHeader.e_phnum
        base = self.__binary[self.__ElfHeader.e_phoff:]
        self.__phdr_l = []

        e_ident = self.__binary[:15]
        ei_data = e_ident[ELFFlags.EI_DATA]

        for _ in range(pdhr_num):
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
        for segment in self.__phdr_l:
            if segment.p_flags & 0x1:
                ret +=  [{
                            "offset"  : segment.p_offset,
                            "size"    : segment.p_memsz,
                            "vaddr"   : segment.p_vaddr,
                            "opcodes" : bytes(self.__binary[segment.p_offset:segment.p_offset + segment.p_memsz]),
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
                            "opcodes" : bytes(self.__binary[section.sh_offset:section.sh_offset + section.sh_size]),
                        }]
        return ret

    def getArch(self):
        if self.__ElfHeader.e_machine == ELFFlags.EM_386 or self.__ElfHeader.e_machine == ELFFlags.EM_X86_64:
            return CS_ARCH_X86
        elif self.__ElfHeader.e_machine == ELFFlags.EM_ARM:
            return CS_ARCH_ARM
        elif self.__ElfHeader.e_machine == ELFFlags.EM_ARM64:
            return CS_ARCH_ARM64
        elif self.__ElfHeader.e_machine == ELFFlags.EM_MIPS:
            return CS_ARCH_MIPS
        elif self.__ElfHeader.e_machine == ELFFlags.EM_PowerPC:
            return CS_ARCH_PPC
        elif self.__ElfHeader.e_machine == ELFFlags.EM_SPARCv8p:
            return CS_ARCH_SPARC
        print("[Error] ELF.getArch() - Architecture not supported")
        return None

    def getArchMode(self):
        if self.__ElfHeader.e_ident[ELFFlags.EI_CLASS] == ELFFlags.ELFCLASS32:
            return CS_MODE_32
        elif self.__ElfHeader.e_ident[ELFFlags.EI_CLASS] == ELFFlags.ELFCLASS64:
            return CS_MODE_64
        print("[Error] ELF.getArchMode() - Bad Arch size")
        return None

    def getEndian(self):
        if self.__ElfHeader.e_ident[ELFFlags.EI_DATA] == ELFFlags.ELFDATA2LSB:
            return 0
        if self.__ElfHeader.e_ident[ELFFlags.EI_DATA] == ELFFlags.ELFDATA2MSB:
            return CS_MODE_BIG_ENDIAN
        print("[Error] ELF.getEndian() - Bad Endianness")
        return None

    def getFormat(self):
        return "ELF"
