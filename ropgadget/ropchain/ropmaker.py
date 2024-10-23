## -*- coding: utf-8 -*-
##
##  Jonathan Salwan - 2014-05-13
##
##  http://shell-storm.org
##  http://twitter.com/JonathanSalwan
##

# Third party library imports
from capstone import *

# Local library imports
from ropgadget.ropchain.arch.ropmakerx64 import ROPMakerX64
from ropgadget.ropchain.arch.ropmakerx86 import ROPMakerX86


class ROPMaker:
    def __init__(self, binary, gadgets, offset):
        self._binary = binary
        self._gadgets = gadgets
        self._offset = offset

        self._handler_arch()

    def _handler_arch(self):
        # Define a mapping of (arch, mode, format) tuples to handler classes
        arch_map = {
            (CS_ARCH_X86, CS_MODE_32, "ELF"): ROPMakerX86,
            (CS_ARCH_X86, CS_MODE_64, "ELF"): ROPMakerX64,
        }

        # Extract the current arch, mode, and format
        arch_info = (
            self._binary.getArch(),
            self._binary.getArchMode(),
            self._binary.getFormat(),
        )

        # Get the corresponding handler class, if it exists
        handler_class = arch_map.get(arch_info)

        if handler_class:
            handler_class(self._binary, self._gadgets, self._offset)
            return

        print(
            f"\n[Error] ROPMaker - Architecture not supported: {arch_info} (CS_ARCH, CS_MODE, format)"
        )
