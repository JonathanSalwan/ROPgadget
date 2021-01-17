## -*- coding: utf-8 -*-
##
##  Jonathan Salwan - 2014-05-12 - ROPgadget tool
##
##  http://twitter.com/JonathanSalwan
##  http://shell-storm.org/project/ROPgadget/
##

import argparse
import sys

from ropgadget.updateAlert import UpdateAlert
from ropgadget.version import *


class Args(object):
    def __init__(self, arguments=None):
        self.__args = None
        custom_arguments_provided = True

        # If no custom arguments are provided, use the program arguments
        if not arguments:
            arguments = sys.argv[1:]
            custom_arguments_provided = False

        self.__parse(arguments, custom_arguments_provided)

    def __parse(self, arguments, custom_arguments_provided=False):
        parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                         description="""description:
  ROPgadget lets you search your gadgets on a binary. It supports several
  file formats and architectures and uses the Capstone disassembler for
  the search engine.

formats supported:
  - ELF
  - PE
  - Mach-O
  - Raw

architectures supported:
  - x86
  - x86-64
  - ARM
  - ARM64
  - MIPS
  - PowerPC
  - Sparc
""",
                                         epilog="""examples:
  ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86
  ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --ropchain
  ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --depth 3
  ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --string "main"
  ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --string "m..n"
  ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --opcode c9c3
  ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --only "mov|ret"
  ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --only "mov|pop|xor|ret"
  ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --filter "xchg|add|sub|cmov.*"
  ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --norop --nosys
  ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --range 0x08041000-0x08042000
  ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --string main --range 0x080c9aaa-0x080c9aba
  ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --memstr "/bin/sh"
  ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --console
  ROPgadget.py --binary ./test-suite-binaries/elf-Linux-x86 --badbytes "00|01-1f|7f|42"
  ROPgadget.py --binary ./test-suite-binaries/Linux_lib64.so --offset 0xdeadbeef00000000
  ROPgadget.py --binary ./test-suite-binaries/elf-ARMv7-ls --depth 5
  ROPgadget.py --binary ./test-suite-binaries/elf-ARM64-bash --depth 5
  ROPgadget.py --binary ./test-suite-binaries/raw-x86.raw --rawArch=x86 --rawMode=32""")

        parser.add_argument("-v", "--version",      action="store_true",              help="Display the ROPgadget's version")
        parser.add_argument("-c", "--checkUpdate",  action="store_true",              help="Checks if a new version is available")
        parser.add_argument("--binary",             type=str, metavar="<binary>",     help="Specify a binary filename to analyze")
        parser.add_argument("--opcode",             type=str, metavar="<opcodes>",    help="Search opcode in executable segment")
        parser.add_argument("--string",             type=str, metavar="<string>",     help="Search string in readable segment")
        parser.add_argument("--memstr",             type=str, metavar="<string>",     help="Search each byte in all readable segment")
        parser.add_argument("--depth",              type=int, metavar="<nbyte>",      default=10, help="Depth for search engine (default 10)")
        parser.add_argument("--only",               type=str, metavar="<key>",        help="Only show specific instructions")
        parser.add_argument("--filter",             type=str, metavar="<key>",        help="Suppress specific mnemonics")
        parser.add_argument("--range",              type=str, metavar="<start-end>",  default="0x0-0x0", help="Search between two addresses (0x...-0x...)")
        parser.add_argument("--badbytes",           type=str, metavar="<byte>",       help="Rejects specific bytes in the gadget's address")
        parser.add_argument("--rawArch",            type=str, metavar="<arch>",       help="Specify an arch for a raw file")
        parser.add_argument("--rawMode",            type=str, metavar="<mode>",       help="Specify a mode for a raw file")
        parser.add_argument("--rawEndian",          type=str, metavar="<endian>",     help="Specify an endianness for a raw file")
        parser.add_argument("--re",                 type=str, metavar="<re>",         help="Regular expression")
        parser.add_argument("--offset",             type=str, metavar="<hexaddr>",    help="Specify an offset for gadget addresses")
        parser.add_argument("--ropchain",           action="store_true",              help="Enable the ROP chain generation")
        parser.add_argument("--thumb",              action="store_true",              help="Use the thumb mode for the search engine (ARM only)")
        parser.add_argument("--console",            action="store_true",              help="Use an interactive console for search engine")
        parser.add_argument("--norop",              action="store_true",              help="Disable ROP search engine")
        parser.add_argument("--nojop",              action="store_true",              help="Disable JOP search engine")
        parser.add_argument("--callPreceded",       action="store_true",              help="Only show gadgets which are call-preceded")
        parser.add_argument("--nosys",              action="store_true",              help="Disable SYS search engine")
        parser.add_argument("--multibr",            action="store_true",              help="Enable multiple branch gadgets")
        parser.add_argument("--all",                action="store_true",              help="Disables the removal of duplicate gadgets")
        parser.add_argument("--noinstr",            action="store_true",              help="Disable the gadget instructions console printing")
        parser.add_argument("--dump",               action="store_true",              help="Outputs the gadget bytes")
        parser.add_argument("--silent",             action="store_true",              help="Disables printing of gadgets during analysis")
        parser.add_argument("--align",              type=int,                         help="Align gadgets addresses (in bytes)")
        parser.add_argument("--mipsrop",            type=str, metavar="<rtype>",      help="MIPS useful gadgets finder stackfinder|system|tails|lia0|registers")

        self.__args = parser.parse_args(arguments)

        if self.__args.noinstr and self.__args.only:
            raise ValueError("[Error] --noinstr and --only=<key> can't be used together")

        if self.__args.noinstr and self.__args.re:
            raise ValueError("[Error] --noinstr and --re=<re> can't be used together")

        if self.__args.version:
            self.__printVersion()
            sys.exit(0)

        elif self.__args.checkUpdate:
            UpdateAlert().checkUpdate()
            sys.exit(0)

        elif self.__args.depth < 2:
            raise ValueError("[Error] The depth must be >= 2")

        elif not custom_arguments_provided and not self.__args.binary and not self.__args.console:
            raise ValueError("[Error] Need a binary filename (--binary/--console or --help)")

        elif self.__args.range:
            try:
                rangeS = int(self.__args.range.split('-')[0], 16)
                rangeE = int(self.__args.range.split('-')[1], 16)
            except:
                raise ValueError("[Error] A range must be set in hexadecimal. Ex: 0x08041000-0x08042000")
            if rangeS > rangeE:
                raise ValueError("[Error] The start value must be greater than end value")

    def __printVersion(self):
        print("Version:        %s" % (PYROPGADGET_VERSION))
        print("Author:         Jonathan Salwan")
        print("Author page:    https://twitter.com/JonathanSalwan")
        print("Project page:   http://shell-storm.org/project/ROPgadget/")

    def getArgs(self):
        return self.__args
