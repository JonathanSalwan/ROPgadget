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

void display_elf_header(void)
{
  fprintf(stdout, "%sELF Header\n", YELLOW);
  fprintf(stdout, "============================================================%s\n\n", ENDC);
  fprintf(stdout, "entry        %s0x%.8x%s\n",	      RED, pElf_Header->e_entry, ENDC);
  fprintf(stdout, "phoff        %s0x%.8x%s\n",        RED, pElf_Header->e_phoff, ENDC);
  fprintf(stdout, "shoff        %s0x%.8x%s\n",        RED, pElf_Header->e_shoff, ENDC);
  fprintf(stdout, "flags        %s0x%.8x%s\n",        RED, pElf_Header->e_flags, ENDC);
  fprintf(stdout, "ehsize       %s0x%.8x (%d)%s\n",   RED, pElf_Header->e_ehsize, pElf_Header->e_ehsize, ENDC);
  fprintf(stdout, "phentsize    %s0x%.8x (%d)%s\n",   RED, pElf_Header->e_phentsize, pElf_Header->e_phentsize, ENDC);
  fprintf(stdout, "phnum        %s0x%.8x (%d)%s\n",   RED, pElf_Header->e_phnum, pElf_Header->e_phnum,ENDC);
  fprintf(stdout, "shentsize    %s0x%.8x (%d)%s\n",   RED, pElf_Header->e_shentsize, pElf_Header->e_shentsize, ENDC);
  fprintf(stdout, "shnum        %s0x%.8x (%d)%s\n",   RED, pElf_Header->e_shnum, pElf_Header->e_shnum,ENDC);
  fprintf(stdout, "shstrndx     %s0x%.8x (%d)%s\n\n\n", RED, pElf_Header->e_shstrndx,  pElf_Header->e_shstrndx,ENDC);
  flag_elfheader = 1;
}

void check_elfheader_mode(char **argv)
{
  int i = 0;

  while (argv[i] != NULL)
    {
      if (!strcmp(argv[i], "-elfheader") && flag_elfheader == 0)
        display_elf_header();
      i++;
    }
}
