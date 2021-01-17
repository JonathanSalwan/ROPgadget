## -*- coding: utf-8 -*-
##
##  Jonathan Salwan - 2014-05-17 - ROPgadget tool
##
##  http://twitter.com/JonathanSalwan
##  http://shell-storm.org/project/ROPgadget/
##

import binascii
import cmd
import re

from capstone import CS_MODE_32

import ropgadget.rgutils as rgutils
from ropgadget.binary import Binary
from ropgadget.gadgets import Gadgets
from ropgadget.options import Options
from ropgadget.ropchain.ropmaker import ROPMaker


class Core(cmd.Cmd):
    def __init__(self, options):
        cmd.Cmd.__init__(self)
        self.__options = options
        self.__binary  = None
        self.__gadgets = []
        self.__offset  = 0
        self.prompt    = '(ROPgadget)> '

    def __checksBeforeManipulations(self):
        if self.__binary is None or self.__binary.getBinary() is None or self.__binary.getArch() is None or self.__binary.getArchMode() is None or self.__binary.getEndian() is None:
            return False
        return True

    def _sectionInRange(self, section):
        """Given a section and a range, edit the section so that all opcodes are within the range"""
        if self.__options.range == "0x0-0x0":
            return section

        rangeStart, rangeEnd = map(lambda x: int(x, 16), self.__options.range.split('-'))

        sectionStart = section['vaddr']
        sectionEnd = sectionStart + section['size']

        opcodes = section['opcodes']
        if rangeEnd < sectionStart or rangeStart > sectionEnd:
            return None
        if rangeStart > sectionStart:
            diff = rangeStart - sectionStart
            opcodes = opcodes[diff:]
            section['vaddr'] += diff
            section['offset'] += diff
            section['size'] -= diff
        if rangeEnd < sectionEnd:
            diff = sectionEnd - rangeEnd
            opcodes = opcodes[:-diff]
            section['size'] -= diff

        if not section['size']:
            return None
        section['opcodes'] = opcodes
        return section

    def __getGadgets(self):
        if not self.__checksBeforeManipulations():
            return False

        G = Gadgets(self.__binary, self.__options, self.__offset)
        execSections = self.__binary.getExecSections()

        # Find ROP/JOP/SYS gadgets
        self.__gadgets = []
        for section in execSections:
            section = self._sectionInRange(section)
            if not section:
                continue
            if not self.__options.norop:
                self.__gadgets += G.addROPGadgets(section)
            if not self.__options.nojop:
                self.__gadgets += G.addJOPGadgets(section)
            if not self.__options.nosys:
                self.__gadgets += G.addSYSGadgets(section)

        # Delete duplicate gadgets
        if not self.__options.all and not self.__options.noinstr:
            self.__gadgets = rgutils.deleteDuplicateGadgets(self.__gadgets)

        # Applicate some Options
        self.__gadgets = Options(self.__options, self.__binary, self.__gadgets).getGadgets()

        # Sorted alphabetically
        if not self.__options.noinstr:
            self.__gadgets = rgutils.alphaSortgadgets(self.__gadgets)

        return True

    def __lookingForGadgets(self):
        if not self.__checksBeforeManipulations():
            return False

        if self.__options.silent:
            return True

        arch = self.__binary.getArchMode()
        print("Gadgets information\n============================================================")
        for gadget in self.__gadgets:
            vaddr = gadget["vaddr"]
            insts = gadget.get("gadget", "")
            insts = " : {}".format(insts) if insts else ""
            bytesStr = " // " + binascii.hexlify(gadget["bytes"]).decode('utf8') if self.__options.dump else ""
            print("0x{{0:0{}x}}{{1}}{{2}}".format(8 if arch == CS_MODE_32 else 16).format(vaddr, insts, bytesStr))

        print("\nUnique gadgets found: %d" % (len(self.__gadgets)))
        return True

    def __lookingForMIPSgadgets(self, mips_option):
        if not self.__checksBeforeManipulations():
            return False

        if self.__options.silent:
            return True

        arch = self.__binary.getArchMode()
        if mips_option == 'stackfinder':
            mipsFindRegex = [r'addiu .*, \$sp']
        elif mips_option == 'system':
            mipsFindRegex = [r'addiu \$a0, \$sp']
        elif mips_option == 'tails':
            mipsFindRegex = [r'lw \$t[0-9], 0x[0-9a-z]{0,4}\(\$s[0-9]', r'move \$t9, \$(s|a|v)']
        elif mips_option == 'lia0':
            mipsFindRegex = [r'li \$a0']
        elif mips_option == 'registers':
            mipsFindRegex = [r'lw \$ra, 0x[0-9a-z]{0,4}\(\$sp']
        else:
            print("Unrecognized option " + mips_option)
            print("Accepted options stackfinder|system|tails|lia0|registers")
            return False

        print("MIPS ROP (" + mips_option + ")\n============================================================")
        self.__getGadgets()

        gadget_counter = 0
        for gadget in self.__gadgets:
            vaddr = gadget["vaddr"]
            insts = gadget.get("gadget", "")
            insts = " : {}".format(insts) if insts else ""
            bytesStr = " // " + binascii.hexlify(gadget["bytes"]).decode('utf8') if self.__options.dump else ""
            for thisRegex in mipsFindRegex:
                toFind = re.findall(thisRegex, insts)
                if toFind:
                    print("0x{{0:0{}x}}{{1}}{{2}}".format(8 if arch == CS_MODE_32 else 16).format(vaddr, insts, bytesStr))
                    gadget_counter += 1

        print("\nUnique gadgets found: %d" % gadget_counter)
        return True

    def __lookingForAString(self, string):
        if not self.__checksBeforeManipulations():
            return False

        if self.__options.silent:
            return True

        dataSections = self.__binary.getDataSections()
        arch = self.__binary.getArchMode()
        print("Strings information\n============================================================")
        for section in dataSections:
            section = self._sectionInRange(section)
            if not section:
                continue
            allRef = [m.start() for m in re.finditer(string.encode(), section["opcodes"])]
            for ref in allRef:
                vaddr  = self.__offset + section["vaddr"] + ref
                match = section["opcodes"][ref:ref + len(string)]
                print("0x{{0:0{}x}} : {{1}}".format(8 if arch == CS_MODE_32 else 16).format(vaddr, match.decode()))
        return True

    def __lookingForOpcodes(self, opcodes):
        if not self.__checksBeforeManipulations():
            return False

        if self.__options.silent:
            return True

        execSections = self.__binary.getExecSections()
        arch = self.__binary.getArchMode()
        print("Opcodes information\n============================================================")
        for section in execSections:
            section = self._sectionInRange(section)
            if not section:
                continue
            allRef = [m.start() for m in re.finditer(re.escape(binascii.unhexlify(opcodes)), section["opcodes"])]
            for ref in allRef:
                vaddr  = self.__offset + section["vaddr"] + ref
                print("0x{{0:0{}x}} : {{1}}".format(8 if arch == CS_MODE_32 else 16).format(vaddr, opcodes))
        return True

    def __lookingForMemStr(self, memstr):
        if  not self.__checksBeforeManipulations():
            return False

        if self.__options.silent:
            return True

        sections  = self.__binary.getExecSections()
        sections += self.__binary.getDataSections()
        arch = self.__binary.getArchMode()
        print("Memory bytes information\n=======================================================")
        chars = list(memstr)
        for char in chars:
            try:
                for section in sections:
                    section = self._sectionInRange(section)
                    if not section:
                        continue
                    allRef = [m.start() for m in re.finditer(char.encode('utf-8'), section["opcodes"])]
                    for ref in allRef:
                        vaddr  = self.__offset + section["vaddr"] + ref
                        print("0x{{0:0{}x}} : '{{1}}'".format(8 if arch == CS_MODE_32 else 16).format(vaddr, char))
                        raise
            except:
                pass
        return True

    def analyze(self):
        try:
            self.__offset = int(self.__options.offset, 16) if self.__options.offset else 0
        except ValueError:
            print("[Error] The offset must be in hexadecimal")
            return False

        if self.__options.console:
            if self.__options.binary:
                self.__binary = Binary(self.__options)
                if not self.__checksBeforeManipulations():
                    return False
            self.cmdloop()
            return True

        self.__binary = Binary(self.__options)
        if not self.__checksBeforeManipulations():
            return False

        if self.__options.string:
            return self.__lookingForAString(self.__options.string)
        elif self.__options.opcode:
            return self.__lookingForOpcodes(self.__options.opcode)
        elif self.__options.memstr:
            return self.__lookingForMemStr(self.__options.memstr)
        elif self.__options.mipsrop:
            return self.__lookingForMIPSgadgets(self.__options.mipsrop)
        else:
            self.__getGadgets()
            self.__lookingForGadgets()
            if self.__options.ropchain:
                ROPMaker(self.__binary, self.__gadgets, self.__offset)
            return True

    def gadgets(self):
        return self.__gadgets

    # Console methods  ============================================
    def do_binary(self, s, silent=False):
        # Do not split the filename with spaces since it might contain
        # whitespaces
        if not s:
            if not silent:
                return self.help_binary()
            return False

        binary = s

        self.__options.binary = binary
        self.__binary = Binary(self.__options)
        if not self.__checksBeforeManipulations():
            return False

        if not silent:
            print("[+] Binary loaded")

    def help_binary(self):
        print("Syntax: binary <file> -- Load a binary")
        return False

    def do_EOF(self, s, silent=False):
        return self.do_quit(s, silent)

    def do_quit(self, s, silent=False):
        return True

    def help_quit(self):
        print("Syntax: quit -- Terminates the application")
        return False

    def do_load(self, s, silent=False):
        if self.__binary is None:
            if not silent:
                print("[-] No binary loaded.")
            return False

        if not silent:
            print("[+] Loading gadgets, please wait...")
        self.__getGadgets()

        if not silent:
            print("[+] Gadgets loaded !")

    def help_load(self):
        print("Syntax: load -- Load all gadgets")
        return False

    def do_display(self, s, silent=False):
        self.__lookingForGadgets()

    def help_display(self):
        print("Syntax: display -- Display all gadgets loaded")
        return False

    def do_depth(self, s, silent=False):
        try:
            depth = int(s.split()[0])
        except:
            if not silent:
                return self.help_depth()
            return False
        if depth <= 0:
            if not silent:
                print("[-] The depth value must be > 0")
            return False
        self.__options.depth = int(depth)

        if not silent:
            print("[+] Depth updated. You have to reload gadgets")

    def help_depth(self):
        print("Syntax: depth <value> -- Set the depth search engine")
        return False

    def do_badbytes(self, s, silent=False):
        try:
            bb = s.split()[0]
        except:
            if not silent:
                return self.help_badbytes()
            else:
                return False
        self.__options.badbytes = bb

        if not silent:
            print("[+] Bad bytes updated. You have to reload gadgets")

    def help_badbytes(self):
        print("Syntax: badbytes <badbyte1|badbyte2...> -- ")
        return False

    def __withK(self, listK, gadget):
        if not listK:
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

    def do_search(self, s, silent=False):
        args = s.split()
        if not len(args):
            return self.help_search()
        withK, withoutK = [], []
        for a in args:
            if a[0] == "!":
                withoutK += [a[1:]]
            else:
                withK += [a]
        if not self.__checksBeforeManipulations():
            if not silent:
                print("[-] You have to load a binary")
            return False
        arch = self.__binary.getArchMode()
        for gadget in self.__gadgets:
            vaddr = gadget["vaddr"]
            insts = gadget["gadget"]
            if self.__withK(withK, insts) and self.__withoutK(withoutK, insts):
                # What to do if silent = True?
                print("0x{{0:0{}x}} : {{1}}".format(8 if arch == CS_MODE_32 else 16).format(vaddr, insts))

    def help_search(self):
        print("Syntax: search <keyword1 keyword2 keyword3...> -- Filter with or without keywords")
        print("keyword  = with")
        print("!keyword = without")
        return False

    def count(self):
        return len(self.__gadgets)

    def do_count(self, s, silent=False):
        if not silent:
            print("[+] %d loaded gadgets." % self.count())

    def help_count(self):
        print("Shows the number of loaded gadgets.")
        return False

    def do_filter(self, s, silent=False):
        try:
            self.__options.filter = s.split()[0]
        except:
            if not silent:
                return self.help_filter()
            return False

        if not silent:
            print("[+] Filter setted. You have to reload gadgets")

    def help_filter(self):
        print("Syntax: filter <filter1|filter2|...> - Suppress specific mnemonics")
        return False

    def do_only(self, s, silent=False):
        try:
            if s.lower() == "none":
                self.__options.only = None
            else:
                self.__options.only = s.split()[0]
        except:
            if not silent:
                return self.help_only()
            return False

        if not silent:
            print("[+] Only setted. You have to reload gadgets")

    def help_only(self):
        print("Syntax: only <only1|only2|...> - Only show specific instructions")
        return False

    def do_range(self, s, silent=False):
        try:
            rangeS = int(s.split('-')[0], 16)
            rangeE = int(s.split('-')[1], 16)
            self.__options.range = s.split()[0]
        except:
            if not silent:
                return self.help_range()
            return False

        if rangeS > rangeE:
            if not silent:
                print("[-] The start value must be greater than the end value")
            return False

        if not silent:
            print("[+] Range setted. You have to reload gadgets")

    def help_range(self):
        print("Syntax: range <start-and> - Search between two addresses (0x...-0x...)")
        return False

    def do_settings(self, s, silent=False):
        print("All:         %s" % self.__options.all)
        print("Badbytes:    %s" % self.__options.badbytes)
        print("Binary:      %s" % self.__options.binary)
        print("Depth:       %s" % self.__options.depth)
        print("Filter:      %s" % self.__options.filter)
        print("Memstr:      %s" % self.__options.memstr)
        print("MultiBr:     %s" % self.__options.multibr)
        print("NoJOP:       %s" % self.__options.nojop)
        print("NoROP:       %s" % self.__options.norop)
        print("NoSYS:       %s" % self.__options.nosys)
        print("Offset:      %s" % self.__options.offset)
        print("Only:        %s" % self.__options.only)
        print("Opcode:      %s" % self.__options.opcode)
        print("ROPchain:    %s" % self.__options.ropchain)
        print("Range:       %s" % self.__options.range)
        print("RawArch:     %s" % self.__options.rawArch)
        print("RawMode:     %s" % self.__options.rawMode)
        print("RawEndian:   %s" % self.__options.rawEndian)
        print("Re:          %s" % self.__options.re)
        print("String:      %s" % self.__options.string)
        print("Thumb:       %s" % self.__options.thumb)
        print("Mipsrop:     %s" % self.__options.mipsrop)

    def help_settings(self):
        print("Display setting's environment")
        return False

    def do_nojop(self, s, silent=False):
        try:
            arg = s.split()[0]
        except:
            return self.help_nojop()

        if arg == "enable":
            self.__options.nojop = True
            if not silent:
                print("[+] NoJOP enable. You have to reload gadgets")

        elif arg == "disable":
            self.__options.nojop = False
            if not silent:
                print("[+] NoJOP disable. You have to reload gadgets")

        else:
            if not silent:
                return self.help_nojop()
            return False

    def help_nojop(self):
        print("Syntax: nojop <enable|disable> - Disable JOP search engin")
        return False

    def do_norop(self, s, silent=False):
        try:
            arg = s.split()[0]
        except:
            return self.help_norop()

        if arg == "enable":
            self.__options.norop = True
            if not silent:
                print("[+] NoROP enable. You have to reload gadgets")

        elif arg == "disable":
            self.__options.norop = False
            if not silent:
                print("[+] NoROP disable. You have to reload gadgets")

        else:
            if not silent:
                return self.help_norop()
            return False

    def help_norop(self):
        print("Syntax: norop <enable|disable> - Disable ROP search engin")
        return False

    def do_nosys(self, s, silent=False):
        try:
            arg = s.split()[0]
        except:
            return self.help_nosys()

        if arg == "enable":
            self.__options.nosys = True
            if not silent:
                print("[+] NoSYS enable. You have to reload gadgets")

        elif arg == "disable":
            self.__options.nosys = False
            if not silent:
                print("[+] NoSYS disable. You have to reload gadgets")

        else:
            if not silent:
                return self.help_nosys()

            return False

    def help_nosys(self):
        print("Syntax: nosys <enable|disable> - Disable SYS search engin")
        return False

    def do_thumb(self, s, silent=False):
        try:
            arg = s.split()[0]
        except:
            return self.help_thumb()

        if arg == "enable":
            self.__options.thumb = True
            if not silent:
                print("[+] Thumb enable. You have to reload gadgets")

        elif arg == "disable":
            self.__options.thumb = False
            if not silent:
                print("[+] Thumb disable. You have to reload gadgets")

        else:
            if not silent:
                return self.help_thumb()
            return False

    def help_thumb(self):
        print("Syntax: thumb <enable|disable> - Use the thumb mode for the search engine (ARM only)")
        return False

    def do_all(self, s, silent=False):
        if s == "enable":
            self.__options.all = True
            if not silent:
                print("[+] Showing all gadgets enabled. You have to reload gadgets")

        elif s == "disable":
            self.__options.all = False
            if not silent:
                print("[+] Showing all gadgets disabled. You have to reload gadgets")

        else:
            if not silent:
                return self.help_all()

            return False

    def help_multibr(self):
        print("Syntax: multibr <enable|disable> - Enable/Disable multiple branch gadgets")
        return False

    def do_multibr(self, s, silent=False):
        if s == "enable":
            self.__options.multibr = True
            if not silent:
                print("[+] Multiple branch gadgets enabled. You have to reload gadgets")

        elif s == "disable":
            self.__options.multibr = False
            if not silent:
                print("[+] Multiple branch gadgets disabled. You have to reload gadgets")

        else:
            if not silent:
                return self.help_all()

            return False

    def help_all(self):
        print("Syntax: all <enable|disable - Show all gadgets (disable removing duplicate gadgets)")
        return False

    def help_re(self):
        print("Syntax: re <pattern1 | pattern2 |...> - Regular expression")
        return False

    def do_re(self, s, silent=False):
        if s.lower() == 'none':
            self.__options.re = None
        elif s == "":
            self.help_re()
            silent = True
        else:
            self.__options.re = s

        if not silent:
            print("[+] Re setted. You have to reload gadgets")
