/*
** RopGadget
** Allan Wirth - http://allanwirth.com/
** Jonathan Salwan - http://twitter.com/JonathanSalwan
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

/* gadget necessary for combo */
/* don't touch this att syntax for parsing */
char *tab_x8632_ropmaker[] =
{
  "mov %eax,(%e?x)",
  "pop %eax", CR_AND,
  "pop %ebx", CR_AND,
  "pop %ecx", CR_AND,
  "pop %edx", CR_AND,
  "xor %eax,%eax", CR_AND,

    "inc %eax", CR_OPT,
    "inc %ax", CR_OPT,
    "inc %al", CR_OPT,

    "int $0x80",
    "sysenter", "pop %ebp", CR_AND,
     CR_OR,
  CR_AND,
  NULL,
};

char *tab_x8632_importsc[] =
{
  "mov %eax,(%edx)",
  "pop %edx", CR_AND,
  "pop %eax", CR_AND,
  NULL,
};
