/*
** RopGadget - Release v3.3.1
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** http://shell-storm.org
** 2011-11-13
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

unsigned int set_cpt_if_mapmode(unsigned int cpt)
{
  Elf32_Addr base_addr;

  base_addr = (pElf32_Phdr->p_vaddr - pElf32_Phdr->p_offset);
  if (mapmode.flag == 0)
    return (cpt);
  else
    return ((unsigned int)(mapmode.addr_start - base_addr));
}

unsigned int check_end_mapmode(unsigned int cpt)
{
  if (mapmode.flag == 0)
    return (0);

  if (cpt + (pElf32_Phdr->p_vaddr - pElf32_Phdr->p_offset) > mapmode.addr_end)
    return (1);
  else
    return (0);
}

static Elf32_Addr get_start(char *str)
{
  Elf32_Addr addr;
  Elf32_Addr base_addr;
  Elf32_Addr end_addr;

  addr = (Elf32_Addr)strtol(str, NULL, 16);
  base_addr = (pElf32_Phdr->p_vaddr - pElf32_Phdr->p_offset);
  end_addr  = (pElf32_Phdr->p_vaddr - pElf32_Phdr->p_offset) + filemode.size;
  if (addr < base_addr)
    {
      fprintf(stderr, "Error value for -map option\n");
      fprintf(stderr, "Map addr need value between 0x%.8x and 0x%.8x\n", base_addr, end_addr);
      exit(EXIT_FAILURE);
    }

  return(addr);
}

static Elf32_Addr get_end(char *str)
{
  Elf32_Addr addr;
  Elf32_Addr base_addr;
  Elf32_Addr end_addr;

  while (*str != '-' && *str != '\0')
    str++;
  if (*str == '-')
    str++;

  addr = (Elf32_Addr)strtol(str, NULL, 16);
  base_addr = (pElf32_Phdr->p_vaddr - pElf32_Phdr->p_offset);
  end_addr  = (pElf32_Phdr->p_vaddr - pElf32_Phdr->p_offset) + filemode.size;
  if (addr > end_addr)
    {
      fprintf(stderr, "Error value for -map option\n");
      fprintf(stderr, "Map addr need value between 0x%.8x and 0x%.8x\n", base_addr, end_addr);
      exit(EXIT_FAILURE);
    }

  return(addr);
}

static void check_error_value(void)
{
  Elf32_Addr base_addr;
  Elf32_Addr end_addr;

  base_addr = (pElf32_Phdr->p_vaddr - pElf32_Phdr->p_offset);
  end_addr  = (pElf32_Phdr->p_vaddr - pElf32_Phdr->p_offset) + filemode.size;
  if (mapmode.addr_start > mapmode.addr_end)
    {
      fprintf(stderr, "Error value for -map option\n");
      fprintf(stderr, "Map addr need value between 0x%.8x and 0x%.8x\n", base_addr, end_addr);
      exit(EXIT_FAILURE);
    }
}

void check_map_mode(char **argv)
{
  int i = 0;

  while (argv[i] != NULL)
    {
      if (!strcmp(argv[i], "-map"))
        {
          if (argv[i + 1] != NULL && argv[i + 1][0] != '\0')
            {
              mapmode.flag = 1;
              mapmode.addr_start = get_start(argv[i + 1]);
              mapmode.addr_end = get_end(argv[i + 1]);
              check_error_value();
            }
          else
            {
              fprintf(stderr, "%sSyntax%s: -map <start-end>\n", RED, ENDC);
              fprintf(stderr, "%sEx%s:     -map 0x08040000-0x08045000\n", RED, ENDC);
              exit(EXIT_FAILURE);
            }
        }
      i++;
    }
}
