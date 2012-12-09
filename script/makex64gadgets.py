#!/usr/bin/python3

# RopGadgetX - Release v3.4.2
# Allan wirth - http://allanwirth.com
# 2012-12-09
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

# takes ATT syntax gadget, returns att, intel, binary forms
temp = tempfile.NamedTemporaryFile(suffix=".o")
def assemble(att):
#  f = "\n".join(att.split(";")) + "\n"
  f = att + "\n"

  s = subprocess.Popen(["as", "--64", "-o", temp.name], stdin=subprocess.PIPE)
  err = s.communicate(f.encode("ascii"))[1]
  if err:
    print(err)

  s3 = subprocess.Popen(["objdump", "-d", temp.name, "-M", "intel"],
      stdout=subprocess.PIPE)
  dump = s3.communicate()[0].decode("ascii").split("\n")[7:]
  # is there a better match to do here?
#  while not b"<.text>" in dump[0]:
#    dump.pop(0)
#  dump.pop(0)
  bin = b""
  intel = []
  for line in dump:
    parts = line.split("\t")
    if len(parts) < 3:
      continue
    bin += bytearray.fromhex(parts[1])
    intel.append(parts[2].strip())
  intel = re.sub("\s+", " ", ";".join(intel)).strip()
  return att, intel, bin

# returns a line for the struct
def asm_line(att, intel, bin):
  hx = "".join('\\' + hex(i)[1:] for i in bin)
  return ('  {{0, 0, "{0}", "{1}", "{2}", {3}}},'.format(att, intel,
      hx, len(bin)))

# takes an instruction and returns all the possible substitutions
def inst_iter(it, dontuse = ()):
  if not "%%" in it:
    return tuple([it])

  res = []
  for gp in gp_registers:
    if gp in dontuse:
      continue
    nit_m = re.search("%%[0-9]", it)
    nit = it.replace(nit_m.group(0), gp)
    res.extend(inst_iter(nit, dontuse + (gp,)))
  return tuple(res)

#### 64bits definitions ####

gp_registers = (
  "%rax", "%rbx", "%rcx", "%rdx", "%rsi", "%rdi", "%rbp", "%rsp", "%r8",
  "%r9", "%r10", "%r11", "%r12", "%r13", "%r14", "%r15"
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
returnables = (
  "pop %%1",
  "push %%1",
  "xor %%1, %%1",
  "inc %%1",
  "dec %%1",
  "div %%1",
  "mul %%1",
  "neg %%1",
  "not %%1",
  "shr %%1",
  "shl %%1",
  "ror %%1",
  "rol %%1",
  "xchg %%1, %%2",
  "bswap %%1",
  "mov %%1, %%2",
  "mov (%%1), %%2",
  "mov %%1, (%%2)"
)

_returnables = tuple(tuple(map(assemble, inst_iter(s))) for s in returnables)
_non_returnables = tuple(tuple(map(assemble, inst_iter(s))) for s in non_returnables)

RET = assemble("ret")

# this is the maximum length we will generate gadgets for
# i.e. the maximum number of instructions that we will put in a row
# before the ret (we will try ALL combinations of this length, so probably
# shouldn't increase past 2)
MAX_GADGET_LENGTH = 1

#### Create the file ####

print ('#include "ropgadget.h"')

print("t_asm tab_x8664[] = ")
print("{")

## Generate all the 'non-returnables' (e.g. non-ret gadgets)
for nr in itertools.chain(*_non_returnables):
  print(asm_line(*nr))

# Generate all the 'returnables' (e.g. all the gadgets that end in ret)
for i in range(1,MAX_GADGET_LENGTH + 1):
  for perm in itertools.permutations(_returnables, i):
    for prod in itertools.product(*perm):
       prod += (RET,)
       att = ";".join(x[0] for x in prod)
       intel = ";".join(x[1] for x in prod)
       bin = b"".join(x[2] for x in prod)
       print(asm_line(att, intel, bin))

print("  {0, 0, NULL, NULL, NULL, 0}")
print("};")
