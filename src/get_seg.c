/*
** RopGadget - Dev v3.3
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** http://shell-storm.org
** 2011-10-18
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "ropgadget.h"

char *get_seg(Elf32_Word seg)
{
  if (seg == 0)
    return ("NULL");
  else if (seg == 1)
    return ("LOAD");
  else if (seg == 2)
    return ("DYNAMIC");
  else if (seg == 3)
    return ("INTERP");
  else if (seg == 4)
    return ("NOTE");
  else if (seg == 5)
    return ("SHLIB");
  else if (seg == 6)
    return ("PHDR");
  else if (seg == 7)
    return ("TLS");
  else if (seg == 8)
    return ("NUM");
  else if (seg == 0x60000000)
    return ("LOOS");
  else if (seg == 0x6fffffff)
    return ("HIOS");
  else if (seg == 0x70000000)
    return ("LOPROC");
  else if (seg == 0x7fffffff)
    return ("HIPROC");
  else if (seg == 0x6474e550)
    return ("EH_FRAME");
  else if (seg == 0x6474e551)
    return ("STACK");
  else if (seg == 0x6474e552)
    return ("RELRO");
  else if (seg == 0x65041580)
    return ("PAX_FLAGS");
  else
    return ("ERROR");
}
