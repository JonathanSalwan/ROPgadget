/*
** RopGadget - Release v3.3.2
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** http://shell-storm.org
** 2012-02-14
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

#define LINUX    pElf_Header->e_ident[EI_OSABI] == ELFOSABI_NONE
#define FREEBSD  pElf_Header->e_ident[EI_OSABI] == ELFOSABI_FREEBSD
#define ELF_F    pElf_Header->e_ident[EI_CLASS] == ELFCLASS32
#define PROC8632 pElf_Header->e_machine == EM_386

void search_gadgets(unsigned char *data, unsigned int size_data)
{
  t_maps_exec   *maps_exec;
  t_maps_read   *maps_read;

  maps_exec = return_maps_exec();
  maps_read = return_maps_read();
  fprintf(stdout, "%sGadgets information\n", YELLOW);
  fprintf(stdout, "============================================================%s\n", ENDC);

  /* Linux/x86-32bits & FreeBSD/x86-32bits*/
  if (ELF_F && (LINUX || FREEBSD) && PROC8632)
    x8632(data, size_data, maps_exec, maps_read);

  if (opcode_mode.flag != 1 && stringmode.flag != 1)
    {
      fprintf(stdout, "\n\n%sPossible combinations.\n", YELLOW);
      fprintf(stdout, "============================================================%s\n\n", ENDC);
      ropmaker();
    }

  free_var_opcode(pVarop);
  free_add_maps_exec(maps_exec);
  free_add_maps_read(maps_read);
}
