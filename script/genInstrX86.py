#!/usr/bin/env python2
## -*- coding: utf-8 -*-
##
##  ROPgadget - Gadgets Table Generator
## 
##  Copyright (C) 2013 - Jonathan Salwan - http://twitter.com/JonathanSalwan
##                       Allan Wirth - http://allanwirth.com/
## 
##  This program is free software: you can redistribute it and/or modify
##  it under the terms of the GNU General Public License as published by
##  the Free Software Foundation, either version 3 of the License, or
##  (at your option) any later version.
##
##  This program is distributed in the hope that it will be useful,
##  but WITHOUT ANY WARRANTY; without even the implied warranty of
##  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##  GNU General Public License for more details.
##
##  You should have received a copy of the GNU General Public License
##  along with this program.  If not, see <http://www.gnu.org/licenses/>.
##

import sys
import commands

class genInstr():

    def __init__(self, arch='32'):
        self._arch = arch

        self._IntelReg64 = ['%rax', '%rbx', '%rcx', '%rdx', '%rdi', '%rsi', '%rbp', '%rsp']
        self._IntelReg32 = ['%eax', '%ebx', '%ecx', '%edx', '%edi', '%esi', '%ebp', '%esp']

        self._IntelBrCompiled = []
        #self._IntelBr = ['call *OP0', 'call *(OP0)', 'jmp *OP0', 'jmp *(OP0)', 'ret']
        self._IntelBr = ['ret']

        self._IntelSyscallCompiled = []
        self._IntelSyscall = ['syscall', 'int $0x80', 'sysenter']

        self._IntelInsCompiled = []
        self._IntelIns = [
                            'pop OP0',
                            'push OP0',
                            'inc OP0',
                            'dec OP0',
                            'div OP0',
                            'mul OP0',
                            'neg OP0',
                            'not OP0',
                            'shr OP0',
                            'shl OP0',
                            'ror OP0',
                            'rol OP0',
                            'bswap OP0',
                            'xor OP0, OP1',
                            'xchg OP0, OP1',
                            'mov OP0, OP1',
                            'mov (OP0), OP1',
                            'mov OP0, (OP1)'
                         ]

        self._IntelX86GadgetsTable = []

    def __str__(self):
        return self._arch

    def _GenIns(self, ins):
        l1 = []

        if self._arch == '32':
            genericReg = self._IntelReg32
        elif self._arch == '64':
            genericReg = self._IntelReg64
        else:
            print 'Only arch 32 and 64 arch supported'
            sys.exit(-1)

        if ins.find('OP0') == -1 and ins.find('OP1') == -1:
            return [ins]

        for regOP0 in genericReg:
            if ins.find('OP1') != -1:
                l2 = []
                for regOP1 in genericReg:
                    l2.append(ins.replace('OP1', regOP1))
                for i in range(len(l2)):
                    l2[i] = l2[i].replace('OP0', regOP0)
                l1 += l2
            else:
                l1.append(ins.replace('OP0', regOP0))
        return l1

    def _epurSpace(self, str):
        while str.find('  ') != -1:
            str = str.replace('  ', ' ')
        if str[-1] == ' ':
            str = str[:-1]
        return str

    def _setHex(self, str):
        str = '\\x' + str.replace(' ', '\\x')
        return str

    def _compileIns(self, ins_l, targetList):
        fd = open('/tmp/ropgadget.temp', 'w')
        for ins in ins_l:
            fd.write(ins + '\n')
        fd.close()

        if self._arch == '64':
            commands.getstatusoutput('as -64 -o /tmp/ropgadget.o /tmp/ropgadget.temp')
        elif self._arch == '32':
            commands.getstatusoutput('as -32 -o /tmp/ropgadget.o /tmp/ropgadget.temp')

        outputIntel = commands.getstatusoutput('objdump -Mintel -d /tmp/ropgadget.o')[1]
        outputAtt = commands.getstatusoutput('objdump -Matt -d /tmp/ropgadget.o')[1]
        outputIntel_l = outputIntel[outputIntel.find('<.text>:'):].split('\n')[1:]
        outputAtt_l = outputAtt[outputAtt.find('<.text>:'):].split('\n')[1:]

        for i in range(len(outputIntel_l)):
            try:
                targetList.append([self._setHex(self._epurSpace(outputIntel_l[i].split('\t')[1])),
                                   self._epurSpace(outputIntel_l[i].split('\t')[2]),
                                   self._epurSpace(outputAtt_l[i].split('\t')[2])])
            except:
                pass
        return

    def assemble(self):

        # IntelIns
        ins = []
        for IntelIns in self._IntelIns:
            ins += self._GenIns(IntelIns)
        self._compileIns(ins, self._IntelInsCompiled)

        # IntelBr
        ins = []
        for IntelBr in self._IntelBr:
            ins += self._GenIns(IntelBr)
        self._compileIns(ins, self._IntelBrCompiled)

        # Syscall
        self._compileIns(self._IntelSyscall, self._IntelSyscallCompiled)

        return

    def _getAllIns(self, ins):
        l = []
        for Intelins in self._IntelInsCompiled:
            try:
                if Intelins[1].split(' ')[0] == ins:
                    l.append(Intelins)
            except:
                if Intelins[1] == ins:
                    l.append(Intelins)

        for Intelins in self._IntelBrCompiled:
            try:
                if Intelins[1].split(' ')[0] == ins:
                    l.append(Intelins)
            except:
                if Intelins[1] == ins:
                    l.append(Intelins)
        return l

    def createGadgets(self):
        
        # Gen severals pop combination
        combi = []
        ret = self._getAllIns('ret')
        allPop = self._getAllIns('pop')
        for pop1 in allPop:
            for pop2 in allPop:
                for pop3 in allPop:
                    combi += [[pop1[0]+pop2[0]+pop3[0]+ret[0][0],
                               pop1[1]+' ; '+pop2[1]+' ; '+pop3[1]+' ; '+ret[0][1],
                               pop1[2]+' ; '+pop2[2]+' ; '+pop3[2]+' ; '+ret[0][2]]]
        self._IntelX86GadgetsTable += combi

        # Gen gadget with branch instruction
        for IntelBr in self._IntelBrCompiled:
            for IntelIns in self._IntelInsCompiled:
                self._IntelX86GadgetsTable += [[IntelIns[0]+IntelBr[0],
                                               IntelIns[1]+' ; '+IntelBr[1],
                                               IntelIns[2]+' ; '+IntelBr[2]]]

        # Gen gadget with interrupt instruction
        for IntelSyscall in self._IntelSyscallCompiled:
            self._IntelX86GadgetsTable += [[IntelSyscall[0],
                                            IntelSyscall[1],
                                            IntelSyscall[2]]]
        return

    def _getSizeOpcode(self, opcode):
        return opcode.count('x')

    def displayGadgetsTable(self):
        print '/* X86 Gadgets Table - ROPgadget generator */\n\n#include "ropgadget.h"\n'
        print 't_asm tab_x86%s[] = \n{' %(self._arch)

        for gadgets in self._IntelX86GadgetsTable:
            print '\t{0, 0, "%s", "%s", "%s", %d},' %(gadgets[2], gadgets[1], gadgets[0], self._getSizeOpcode(gadgets[0]))

        print '\t{0, 0, NULL, NULL, NULL, 0}'
        print '};'
        return

if __name__ == '__main__':

    if len(sys.argv) < 2:
        print 'Syntax: %s <32 | 64>' %(sys.argv[0])
        sys.exit(0)

    obj = genInstr(sys.argv[1])
    obj.assemble()
    obj.createGadgets()
    obj.displayGadgetsTable()

    sys.exit(0)

