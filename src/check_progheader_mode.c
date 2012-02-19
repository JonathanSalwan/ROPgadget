/*
** RopGadget - Release v3.3.3
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** http://shell-storm.org
** 2012-02-19
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

void display_program_header()
{
  int x = 0;

  fprintf(stdout, "%sProgram Header\n", YELLOW);
  fprintf(stdout, "============================================================%s\n\n", ENDC);
  while (x != pElf_Header->e_phnum)
    {
      fprintf(stdout, "%s%s%s\n", YELLOW, get_seg(pElf32_Phdr->p_type), ENDC);
      fprintf(stdout, "\toffset ");
      fprintf(stdout, "%s0x%.8x%s ",  RED, pElf32_Phdr->p_offset, ENDC);
      fprintf(stdout, "vaddr ");
      fprintf(stdout, "%s0x%.8x%s ",  RED, pElf32_Phdr->p_vaddr, ENDC);
      fprintf(stdout, "paddr ");
      fprintf(stdout, "%s0x%.8x%s\n", RED, pElf32_Phdr->p_paddr, ENDC);
      fprintf(stdout, "\tfilesz ");
      fprintf(stdout, "%s0x%.8x%s ",  RED, pElf32_Phdr->p_filesz, ENDC);
      fprintf(stdout, "memsz ");
      fprintf(stdout, "%s0x%.8x%s ",  RED, pElf32_Phdr->p_memsz, ENDC);
      fprintf(stdout, "flags ");
      fprintf(stdout, "%s%s%s\n",   RED, get_flags(pElf32_Phdr->p_flags), ENDC);
      x++;
      pElf32_Phdr++;
    }
    pElf32_Phdr -= x;
    flag_progheader = 1;
    fprintf(stdout, "\n\n");
}

void check_progheader_mode(char **argv)
{
  int i = 0;

  while (argv[i] != NULL)
    {
      if (!strcmp(argv[i], "-progheader") && flag_progheader == 0)
        display_program_header();
      i++;
    }
}
