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

unsigned int set_cpt_if_mapmode(unsigned int cpt)
{
  Elf32_Addr base_addr;

  base_addr = (pElf32_Phdr->p_vaddr - pElf32_Phdr->p_offset);
  return (mapmode.flag == 0)?cpt:(mapmode.addr_start - base_addr);
}

unsigned int check_end_mapmode(unsigned int cpt)
{
  return (mapmode.flag && cpt + (pElf32_Phdr->p_vaddr - pElf32_Phdr->p_offset) > mapmode.addr_end);
}

void map_parse(char *str)
{
  Elf32_Addr base_addr;
  Elf32_Addr end_addr;

  base_addr = (pElf32_Phdr->p_vaddr - pElf32_Phdr->p_offset);
  end_addr  = (pElf32_Phdr->p_vaddr - pElf32_Phdr->p_offset) + filemode.size;

  mapmode.addr_start = (Elf32_Addr)strtol(str, NULL, 16);

  while (*str != '-' && *str != '\0')
    str++;
  if (*str == '-')
    str++;

  mapmode.addr_end = (Elf32_Addr)strtol(str, NULL, 16);

  if (mapmode.addr_start < base_addr || mapmode.addr_end > end_addr || mapmode.addr_start > mapmode.addr_end)
    {
      fprintf(stderr, "Error value for -map option\n");
      fprintf(stderr, "Map addr need value between 0x%.8x and 0x%.8x\n", base_addr, end_addr);
      exit(EXIT_FAILURE);
    }
}
