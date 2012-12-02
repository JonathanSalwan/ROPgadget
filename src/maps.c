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

/* function for add a new element in linked list | save a read/exec map */
static t_map *add_map(t_map *old_element, Address addr_start, Address addr_end)
{
  t_map *new_element;

  new_element = xmalloc(sizeof(t_map));
  new_element->addr_start = addr_start;
  new_element->addr_end   = addr_end;
  new_element->next       = old_element;

  return (new_element);
}

/* free linked list */
void free_add_map(t_map *element)
{
  t_map *tmp;

  while(element)
    {
      tmp = element;
      element = element->next;
      free(tmp);
    }
}

/* check if flag have a READ BIT */
static int check_read_flag(Elf32_Word flag)
{
  return (flag > 3);
}

/* check if flag have a EXEC BIT */
static int check_exec_flag(Elf32_Word flag)
{
  return (flag%2 == 1);
}

/* return linked list with maps read/exec segment */
t_map *return_map(int read)
{
  int  x;
  t_map *map;

  map = NULL;
  for (x = 0; x != pElf_Header->e_phnum; x++, pElf32_Phdr++)
    if (read?check_read_flag(pElf32_Phdr->p_flags):check_exec_flag(pElf32_Phdr->p_flags))
      map = add_map(map, pElf32_Phdr->p_vaddr, (Address)(pElf32_Phdr->p_vaddr + pElf32_Phdr->p_memsz));

  pElf32_Phdr -= x;

  return map;
}

/* Check if phdr have a READ/EXEC bit */
int check_maps(t_map *read_maps, Address addr)
{
  for (; read_maps != NULL; read_maps = read_maps->next)
    if (addr >= read_maps->addr_start && addr <= read_maps->addr_end)
      return TRUE;

  return FALSE;
}

/* Set mapmode */

unsigned int set_cpt_if_mapmode(unsigned int cpt)
{
  Address base_addr;

  base_addr = (pElf32_Phdr->p_vaddr - pElf32_Phdr->p_offset);
  return (mapmode.flag == 0)?cpt:(mapmode.addr_start - base_addr);
}

unsigned int check_end_mapmode(unsigned int cpt)
{
  return (mapmode.flag && cpt + (pElf32_Phdr->p_vaddr - pElf32_Phdr->p_offset) > mapmode.addr_end);
}

void map_parse(char *str)
{
  Address base_addr;
  Address end_addr;

  base_addr = (pElf32_Phdr->p_vaddr - pElf32_Phdr->p_offset);
  end_addr  = (pElf32_Phdr->p_vaddr - pElf32_Phdr->p_offset) + filemode.size;

  mapmode.addr_start = (Address)strtol(str, NULL, 16);

  while (*str != '-' && *str != '\0')
    str++;
  if (*str == '-')
    str++;

  mapmode.addr_end = (Address)strtol(str, NULL, 16);

  if (mapmode.addr_start < base_addr || mapmode.addr_end > end_addr || mapmode.addr_start > mapmode.addr_end)
    {
      fprintf(stderr, "Error value for -map option\n");
      fprintf(stderr, "Map addr need value between " ADDR_FORMAT " and " ADDR_FORMAT "\n", base_addr, end_addr);
      exit(EXIT_FAILURE);
    }
}
