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

void search_gadgets(unsigned char *data, unsigned int size_data)
{
  t_map   *maps_exec;
  t_map   *maps_read;

  maps_exec = return_map(0);
  maps_read = return_map(1);
  fprintf(stdout, "%sGadgets information\n", YELLOW);
  fprintf(stdout, "============================================================%s\n", ENDC);

  /* Linux/x86-32bits & FreeBSD/x86-32bits*/
  if (ELF_F && (SYSV || LINUX || FREEBSD) && PROC8632)
    find_all_gadgets(data, size_data, maps_exec, maps_read, tab_x8632);

  if (opcode_mode.flag != 1 && stringmode.flag != 1)
    {
      fprintf(stdout, "\n\n%sPossible combinations.\n", YELLOW);
      fprintf(stdout, "============================================================%s\n\n", ENDC);
      x8632_ropmaker();
    }

  free_list_inst(pVarop);
  free_add_map(maps_exec);
  free_add_map(maps_read);

  if (opcode_mode.flag == 1)
    fprintf(stdout, "\nTotal opcodes found: %s%d%s\n", YELLOW, NbTotalGadFound, ENDC);
  else if (stringmode.flag == 1)
    fprintf(stdout, "\nTotal strings found: %s%d%s\n", YELLOW, NbTotalGadFound, ENDC);
  else
    fprintf(stdout, "\nUnique gadgets found: %s%d%s\n", YELLOW, NbGadFound, ENDC);
}
