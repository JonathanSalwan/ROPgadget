#!/usr/bin/python3

# RopGadget
# Allan wirth - http://allanwirth.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

import subprocess
import tempfile
import re
import itertools

# takes ATT syntax gadgets, returns att, intel, binary forms
def assemble(atts):
  temp = tempfile.NamedTemporaryFile(suffix=".o")

  f = "\n".join(atts) + "\n"

  s = subprocess.Popen(["as", "--64", "-o", temp.name], stdin=subprocess.PIPE)
  err = s.communicate(f.encode("ascii"))[1]
  if err:
    print(err)

  s3 = subprocess.Popen(["objdump", "-d", temp.name, "-M", "intel"],
      stdout=subprocess.PIPE)
  dump = s3.communicate()[0].decode("ascii").split("\n")[7:]
  bins = []
  intels = []
  for line in dump:
    parts = line.split("\t")
    if len(parts) < 3:
      continue
    bins.append(b'' + bytearray.fromhex(parts[1]))
    intels.append(re.sub("\s+", " ", parts[2].strip()))
  return zip(atts, intels, bins)

# returns a line for the struct
def asm_line(att, intel, bin):
  hx = "".join('\\' + hex(i)[1:] for i in bin)
  return ('  {{0, 0, "{0}", "{1}", "{2}", {3}}},'.format(att, intel,
      hx, len(bin)))

# takes an instruction and returns all the possible substitutions
def inst_iter(it, dontuse = (), gpz = None):
  if gpz is None:
    gpz = gp_registers
  if not "%%" in it:
    return tuple([it])

  res = []
  for gp in gpz:
    if gp in dontuse:
      continue
    nit_m = re.search("%%[0-9]", it)
    nit = it.replace(nit_m.group(0), gp)
    res.extend(inst_iter(nit, dontuse + (gp,)))
  return tuple(res)

#### 64bits definitions ####

gp_registers = (
  "%rax", "%rbx", "%rcx", "%rdx", "%rsi", "%rdi", "%rbp", "%rsp",
# If I were to generate all of these it would be very large.
#  "%r8",  "%r9", "%r10", "%r11", "%r12", "%r13", "%r14", "%r15"
)

epilogue_registers = (
  "%rbx", "%rbp",
  "%r12", "%r13", "%r14", "%r15"
# these are used in epilogues, but only in certain orders
# and only on very long epilogues anyway
)

# holds gadgets that don't need a return after them
non_returnables = (
  "syscall",
  "call *%%1",
  "call *(%%1)",
  "jmp *%%1",
  "jmp *(%%1)"
)

# holds gadgets that we'll want if they have a return after them
# the number is priority / how deep we go with them
# Note: All the ones that have >1 are the ones that are used by ropgadget
# for auto exploit generation.
returnables = (
  ("pop %%1", 2),
  ("push %%1", 1),
  ("xor %%1,%%1", 1),
  ("inc %%1", 1),
  ("dec %%1", 1),
  ("div %%1", 1),
  ("mul %%1", 1),
  ("neg %%1", 1),
  ("not %%1", 1),
  ("shr %%1", 0),
  ("shl %%1", 0),
  ("ror %%1", 0),
  ("rol %%1", 0),
  ("xchg %%1,%%2", 1),
  ("bswap %%1", 1),
  ("mov %%1,%%2", 1),
  ("mov (%%1),%%2", 1),
  ("mov %%1,(%%2)", 1),

# these ones we NEED for automatic payload generation
  ("inc %eax", 1),
  ("xor %eax,%eax", 2),
  ("inc %ax", 1),
  ("inc %al", 1),
  ("inc %rax", 1),
#  ("addb $0x1, %al", 0),
#  ("addw $0x1, %ax", 0),
#  ("addl $0x1, %eax", 0),
#  ("addq $0x1, %rax", 0),
)

_filler = tuple(assemble(inst_iter("pop %%1", gpz=epilogue_registers)))

_returnables = tuple((tuple(assemble(inst_iter(s[0]))),s[1]) for s in returnables)
_non_returnables = tuple(tuple(assemble(inst_iter(s))) for s in non_returnables)

RET = list(assemble(["ret"]))[0]

#### Create the file ####

print ('#include "ropgadget.h"')

print("t_asm tab_x8664[] = ")
print("{")

## Generate all the 'non-returnables' (e.g. non-ret gadgets)
for nr in itertools.chain(*_non_returnables):
  print(asm_line(*nr))

# Generate all the 'returnables' (e.g. all the gadgets that end in ret)
for r in _returnables:
  for a in r[0]:
    for i in range(0, r[1]+1):
      for perm in itertools.permutations(_filler, i):
        prod = (a,) + perm + (RET,)
        att = ";".join(x[0] for x in prod)
        intel = ";".join(x[1] for x in prod)
        bin = b"".join(x[2] for x in prod)
        print(asm_line(att, intel, bin))

print("  {0, 0, NULL, NULL, NULL, 0}")
print("};")
