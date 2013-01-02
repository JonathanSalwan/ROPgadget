/*
** RopGadget - Release v3.4.2
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** Allan Wirth - http://allanwirth.com/
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

void search_gadgets(t_binary *bin)
{
  unsigned int NbGadFound = 0;
  unsigned int NbTotalGadFound = 0;

  if (asm_mode.flag)
    {
      if (bin->processor == PROCESSOR_X8632 || bin->processor == PROCESSOR_X8664)
        x86_build_code(asm_mode.string);
      else
        {
          fprintf(stderr, "Assembly building mode not available for this architecture.\n");
          return;
        }
    }

  fprintf(stdout, "%sGadgets information\n", YELLOW);
  fprintf(stdout, "============================================================%s\n", ENDC);

  /* Linux/x86-32bits & FreeBSD/x86-32bits*/
  if (bin->processor == PROCESSOR_X8632)
    find_all_gadgets(bin, tab_x8632, &NbGadFound, &NbTotalGadFound);
  else if (bin->processor == PROCESSOR_X8664)
    find_all_gadgets(bin, tab_x8664, &NbGadFound, &NbTotalGadFound);
  else
    {
      fprintf(stderr, "Gadget searching not supported for this architecture.\n");
      return;
    }

  if (!opcode_mode.flag && !stringmode.flag)
    {
      fprintf(stdout, "\n\n%sPossible combinations.\n", YELLOW);
      fprintf(stdout, "============================================================%s\n\n", ENDC);
      if (bin->processor == PROCESSOR_X8632)
        x86_ropmaker(4);
      else if (bin->processor == PROCESSOR_X8664)
        x86_ropmaker(8);
      else
        {
          fprintf(stderr, "Ropmaking not supported for this architecture.\n");
          return;
        }
    }

  if (opcode_mode.flag == 1)
    fprintf(stdout, "\nTotal opcodes found: %s%u%s\n", YELLOW, NbTotalGadFound, ENDC);
  else if (stringmode.flag == 1)
    fprintf(stdout, "\nTotal strings found: %s%u%s\n", YELLOW, NbTotalGadFound, ENDC);
  else
    fprintf(stdout, "\nUnique gadgets found: %s%u%s\n", YELLOW, NbGadFound, ENDC);
}
