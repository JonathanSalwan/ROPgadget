/*
** RopGadget - Release v3.3
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** http://shell-storm.org
** 2011-11-07
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

void display_section_header(void)
{
  char *ptrNameSection;
  int x = 0;

  while(x != pElf_Header->e_shnum)
    {
      if (pElf32_Shdr->sh_type == SHT_STRTAB && pElf32_Shdr->sh_addr == 0)
        {
          ptrNameSection =  (char *)pMapElf + pElf32_Shdr->sh_offset;
          break;
        }
      x++;
      pElf32_Shdr++;
    }
    pElf32_Shdr -= x;
    x = 0;

    fprintf(stdout, "%sSection Header\n", YELLOW);
    fprintf(stdout, "============================================================%s\n\n", ENDC);
    fprintf(stdout, "%sidx\taddr\t\tsize\t\tsection%s\n", GREEN, ENDC);
    while (x != pElf_Header->e_shnum)
      {
        fprintf(stdout, "%s%.2d%s\t", GREEN, x, ENDC);
        fprintf(stdout, "%s0x%.8x\t", RED, pElf32_Shdr->sh_addr);
        fprintf(stdout, "0x%.8x\t%s", pElf32_Shdr->sh_size, ENDC);
        fprintf(stdout, "%s\n", (char *)(ptrNameSection + pElf32_Shdr->sh_name));
        x++;
        pElf32_Shdr++;
      }
    pElf32_Shdr -= x;
    flag_sectheader = 1;
    fprintf(stdout, "\n\n");
}

void check_sectheader_mode(char **argv)
{
  int i = 0;

  while (argv[i] != NULL)
    {
      if (!strcmp(argv[i], "-sectheader") && flag_sectheader == 0)
        display_section_header();
      i++;
    }
}
