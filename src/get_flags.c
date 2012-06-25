/*
** RopGadget - Release v3.3.4
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** http://shell-storm.org
** 2012-06-25
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

char *get_flags(Elf32_Word flags)
{
  if (flags == 0)
    return ("---");
  else if (flags == 1)
    return ("--x");
  else if (flags == 2)
    return ("-w-");
  else if (flags == 3)
    return ("-wx");
  else if (flags == 4)
    return ("r--");
  else if (flags == 5)
    return ("r-x");
  else if (flags == 6)
    return ("rw-");
  else if (flags == 7)
    return ("rwx");
  else
    return ("Err");
}
