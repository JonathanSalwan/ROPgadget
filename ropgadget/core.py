#!/usr/bin/env python2
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

import cmd
import os
import re
import rgutils
import sqlite3

from binary             import Binary
from capstone           import CS_MODE_32
from gadgets            import Gadgets
from options            import Options
from ropchain.ropmaker  import ROPMaker

class Core(cmd.Cmd):
    def __init__(self, options):
        cmd.Cmd.__init__(self)
        self.__options = options
        self.__binary  = None
        self.__gadgets = []
        self.prompt    = '(ROPgadget)> '


    def __checksBeforeManipulations(self):
        if self.__binary == None or self.__binary.getBinary() == None or self.__binary.getArch() == None or self.__binary.getArchMode() == None:
            return False
        return True


    def __getAllgadgets(self):

        if self.__checksBeforeManipulations() == False:
            return False

        G = Gadgets(self.__binary, self.__options)
        execSections = self.__binary.getExecSections()

        # Find ROP/JOP/SYS gadgets
        self.__gadgets = []
        for section in execSections:
            if not self.__options.norop: self.__gadgets += G.addROPGadgets(section)
            if not self.__options.nojop: self.__gadgets += G.addJOPGadgets(section)
            if not self.__options.nosys: self.__gadgets += G.addSYSGadgets(section)

        # Pass clean single instruction and unknown instructions
        self.__gadgets = G.passClean(self.__gadgets)

        # Delete duplicate gadgets
        self.__gadgets = rgutils.deleteDuplicateGadgets(self.__gadgets)

        # Applicate some Options
        self.__gadgets = Options(self.__options, self.__binary, self.__gadgets).getGadgets()

        # Sorted alphabetically
        self.__gadgets = rgutils.alphaSortgadgets(self.__gadgets)

        return True


    def __lookingForGadgets(self):

        if self.__checksBeforeManipulations() == False:
            return False

        arch = self.__binary.getArchMode()
        print "Gadgets information\n============================================================"
        for gadget in self.__gadgets:
            vaddr = gadget["vaddr"]
            insts = gadget["gadget"]
            print ("0x%08x" %(vaddr) if arch == CS_MODE_32 else "0x%016x" %(vaddr)) + " : %s" %(insts)
        print "\nUnique gadgets found: %d" %(len(self.__gadgets))
        return True


    def __lookingForAString(self, string):

        if self.__checksBeforeManipulations() == False:
            return False

        dataSections = self.__binary.getDataSections()
        arch = self.__binary.getArchMode()
        print "Strings information\n============================================================"
        for section in dataSections:
            allRef = [m.start() for m in re.finditer(string, section["opcodes"])]
            for ref in allRef:
                try:
                    off = int(self.__options.offset, 16) if self.__options.offset else 0
                except ValueError:
                    print "[Error] __lookingForAString() - The offset must be in hexadecimal"
                    return False
                vaddr = off+section["vaddr"]+ref
                string = section["opcodes"][ref:ref+len(string)]
                rangeS = int(self.__options.range.split('-')[0], 16)
                rangeE = int(self.__options.range.split('-')[1], 16)
                if (rangeS == 0 and rangeE == 0) or (vaddr >= rangeS and vaddr <= rangeE):
                    print ("0x%08x" %(vaddr) if arch == CS_MODE_32 else "0x%016x" %(vaddr)) + " : %s" %(string)
        return True


    def __lookingForOpcodes(self, opcodes):

        if self.__checksBeforeManipulations() == False:
            return False

        execSections = self.__binary.getExecSections()
        arch = self.__binary.getArchMode()
        print "Opcodes information\n============================================================"
        for section in execSections:
            allRef = [m.start() for m in re.finditer(opcodes.decode("hex"), section["opcodes"])]
            for ref in allRef:
                try:
                    off = int(self.__options.offset, 16) if self.__options.offset else 0
                except ValueError:
                    print "[Error] __lookingForOpcodes() - The offset must be in hexadecimal"
                    return False
                vaddr = off+section["vaddr"]+ref
                rangeS = int(self.__options.range.split('-')[0], 16)
                rangeE = int(self.__options.range.split('-')[1], 16)
                if (rangeS == 0 and rangeE == 0) or (vaddr >= rangeS and vaddr <= rangeE):
                    print ("0x%08x" %(vaddr) if arch == CS_MODE_32 else "0x%016x" %(vaddr)) + " : %s" %(opcodes)
        return True


    def __lookingForMemStr(self, memstr):

        if self.__checksBeforeManipulations() == False:
            return False

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
                        try:
                            off = int(self.__options.offset, 16) if self.__options.offset else 0
                        except ValueError:
                            print "[Error] __lookingForMemStr() - The offset must be in hexadecimal"
                            return False
                        vaddr = off+section["vaddr"]+ref
                        rangeS = int(self.__options.range.split('-')[0], 16)
                        rangeE = int(self.__options.range.split('-')[1], 16)
                        if (rangeS == 0 and rangeE == 0) or (vaddr >= rangeS and vaddr <= rangeE):
                            print ("0x%08x" %(vaddr) if arch == CS_MODE_32 else "0x%016x" %(vaddr)) + " : '%c'" %(char)
                            raise
            except:
                pass
        return True


    def analyze(self):

        if self.__options.console:
            if self.__options.binary:
                self.__binary = Binary(self.__options)
                if self.__checksBeforeManipulations() == False:
                    return False
            self.cmdloop()
            return True

        self.__binary = Binary(self.__options)
        if self.__checksBeforeManipulations() == False:
            return False

        if   self.__options.string:   return self.__lookingForAString(self.__options.string)
        elif self.__options.opcode:   return self.__lookingForOpcodes(self.__options.opcode)
        elif self.__options.memstr:   return self.__lookingForMemStr(self.__options.memstr)
        else: 
            self.__getAllgadgets()
            self.__lookingForGadgets()
            if self.__options.ropchain:
                ROPMaker(self.__binary, self.__gadgets)
            return True








    # Console methods  ============================================

    def do_binary(self, s):
        try:
            binary = s.split()[0]
        except:
            return self.help_binary()
        self.__options.binary = binary
        self.__binary = Binary(self.__options)
        if self.__checksBeforeManipulations() == False:
            return False
        print "[+] Binary loaded"


    def help_binary(self):
        print "Syntax: binary <file> -- Load a binary"
        return False


    def do_quit(self, s):
        return True


    def help_quit(self):
        print "Syntax: quit -- Terminates the application"
        return False


    def do_load(self, s):

        if self.__binary == None:
            print "[-] No binary loaded."
            return False

        print "[+] Loading gadgets, please wait..."
        self.__getAllgadgets()
        print "[+] Gadgets loaded !"

        
    def help_load(self):
        print "Syntax: load -- Load all gadgets"
        return False


    def do_display(self, s):
        self.__lookingForGadgets()


    def help_display(self):
        print "Syntax: display -- Display all gadgets loaded"
        return False


    def do_depth(self, s):
        try:
            depth = int(s.split()[0])
        except:
            return self.help_depth()
        if depth <= 0:
            print "[-] The depth value must be > 0"
            return
        self.__options.depth = int(depth)
        print "[+] Depth updated. You have to reload gadgets"


    def help_depth(self):
        print "Syntax: depth <value> -- Set the depth search engine"
        return False


    def do_badbytes(self, s):
        try:
            bb = s.split()[0]
        except:
            return self.help_badbytes()
        self.__options.badbytes = bb
        print "[+] Bad bytes updated. You have to reload gadgets"


    def help_badbytes(self):
        print "Syntax: badbytes <badbyte1|badbyte2...> -- "
        return False


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
        withK, withoutK = [], []
        for a in args:
            if a[0:1] == "!":
                withoutK += [a[1:]]
            else:
                withK += [a]
        if self.__checksBeforeManipulations() == False:
            print "[-] You have to load a binary"
            return False
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
        return False


    def do_count(self, s):
        print "[+] %d loaded gadgets." % len(self.__gadgets)


    def help_count(self):
        print "Shows the number of loaded gadgets."
        return False


    def do_filter(self, s):
        try:
            self.__options.filter = s.split()[0]
        except:
            return self.help_filter()
        print "[+] Filter setted. You have to reload gadgets"


    def help_filter(self):
        print "Syntax: filter <filter1|filter2|...> - Suppress specific instructions"
        return False


    def do_only(self, s):
        try:
            self.__options.only = s.split()[0]
        except:
            return self.help_only()
        print "[+] Only setted. You have to reload gadgets"


    def help_only(self):
        print "Syntax: only <only1|only2|...> - Only show specific instructions"
        return False


    def do_range(self, s):
            try:
                rangeS = int(s.split('-')[0], 16)
                rangeE = int(s.split('-')[1], 16)
                self.__options.range = s.split()[0]
            except:
                return self.help_range()

            if rangeS > rangeE:
                print "[-] The start value must be greater than the end value"
                return False

            print "[+] Range setted. You have to reload gadgets"


    def help_range(self):
        print "Syntax: range <start-and> - Search between two addresses (0x...-0x...)"
        return False


    def do_settings(self, s):
        print "Badbytes:    %s" %(self.__options.badbytes)
        print "Binary:      %s" %(self.__options.binary)
        print "Depth:       %s" %(self.__options.depth)
        print "Filter:      %s" %(self.__options.filter)
        print "Memstr:      %s" %(self.__options.memstr)
        print "NoJOP:       %s" %(self.__options.nojop)
        print "NoROP:       %s" %(self.__options.norop)
        print "NoSYS:       %s" %(self.__options.nosys)
        print "Offset:      %s" %(self.__options.offset)
        print "Only:        %s" %(self.__options.only)
        print "Opcode:      %s" %(self.__options.opcode)
        print "Range:       %s" %(self.__options.range)
        print "RawArch:     %s" %(self.__options.rawArch)
        print "RawMode:     %s" %(self.__options.rawMode)
        print "ROPchain:    %s" %(self.__options.ropchain)
        print "String:      %s" %(self.__options.string)
        print "Thumb:       %s" %(self.__options.thumb)


    def help_settings(self):
        print "Display setting's environment"
        return False

    def do_nojop(self, s):
        try:
            arg = s.split()[0]
        except:
            return self.help_nojop()

        if arg == "enable":
            self.__options.nojop = True
            print "[+] NoJOP enable. You have to reload gadgets"

        elif arg == "disable":
            self.__options.nojop = False
            print "[+] NoJOP disable. You have to reload gadgets"

        else:
            return self.help_nojop()


    def help_nojop(self):
        print "Syntax: nojop <enable|disable> - Disable JOP search engin"
        return False


    # FIXME: Works before the commit 1abb25634c4a2afdbf2f8a568bc9e4dcacf566eb
    #        Now, save2db must save all binary informations accessible in Binary().
    #        Then, loaddb must create a Binary object.
    #        Why? Because now it's possible to run ROPgadget only in console mode and
    #        load a binary or db. That's why, if we load an db file, we need all information
    #        about the binary loaded.

    #def do_save2db(self, s):
    #    db_name = s.strip()
    #    if not db_name:
    #        return self.help_save2db()

    #    print "[+] Saving %d gadgets to database %s..." % (len(self.__gadgets), db_name)

    #    try:
    #        db = sqlite3.connect(db_name)
    #    except sqlite3.OperationalError, e:
    #        print "[-] There was an error when trying to create the database: %s" % e
    #        return

    #    cursor = db.cursor()
    #    cursor.execute("DROP TABLE IF EXISTS gadgets")
    #    cursor.execute("CREATE TABLE gadgets(id INTEGER PRIMARY KEY, gadget TEXT, vaddr INTEGER)")
    #    db.commit()

    #    for index, gadget in enumerate(self.__gadgets):
    #        cursor.execute("INSERT INTO gadgets(id, gadget, vaddr) VALUES (?,?,?)", (index, gadget["gadget"], gadget["vaddr"]))
    #    db.commit()
    #    db.close()
    #    print "[+] Done."


    #def help_save2db(self):
    #    print "Saves the loaded gadgets to an sqlite database."
    #    print "Usage: save2db <db_filename>"


    #def do_loaddb(self, s):
    #    db_name = s.strip()
    #    if not db_name:
    #        return self.help_loaddb()

    #    print "[+] Loading gadgets from database %s..." % db_name
    #    if not os.path.isfile(db_name):
    #        print "[-] Error: %s: no such file." % db_name
    #        return

    #    try:
    #        db = sqlite3.connect(db_name)
    #    except sqlite3.OperationalError, e:
    #        print "[-] There was an error when trying to create the database: %s" % e
    #        return
    #
    #    cursor = db.cursor()
    #    try:
    #        cursor.execute("SELECT * FROM gadgets")
    #    except sqlite3.OperationalError, e:
    #        print "[-] There was an error when running a SELECT query: %s" % e
    #        db.close()
    #        return
    #    all_rows = cursor.fetchall()
    #    db.close()

    #    self.__gadgets = []
    #    for row in all_rows:
    #        self.__gadgets.append({"gadget": row[1], "vaddr": row[2]})

    #    print "[+] Finished loading %d gadgets." % len(all_rows)


    #def help_loaddb(self):
    #    print "Loads gadgets from an sqlite database."
    #    print "Usage: loaddb <db_filename>"

