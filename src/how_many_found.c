/*
** RopGadget - Release v3.4.2
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** http://shell-storm.org
** 2012-11-11
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

void how_many_found()
{
  if (opcode_mode.flag == 1)
    fprintf(stdout, "\nTotal opcodes found: %s%d%s\n", YELLOW, NbTotalGadFound, ENDC);
  else if (stringmode.flag == 1)
    fprintf(stdout, "\nTotal strings found: %s%d%s\n", YELLOW, NbTotalGadFound, ENDC);
  else
    fprintf(stdout, "\nUnique gadgets found: %s%d%s\n", YELLOW, NbGadFound, ENDC);
}
