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

/* function for add a new element in linked list | save a read/exec map */
static t_map *add_map(t_map *old_element, Elf32_Addr addr_start, Elf32_Addr addr_end)
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
  for (x = 0; x != pElf_Header->e_phnum; x++)
    {
      if (read?check_read_flag(pElf32_Phdr->p_flags):check_exec_flag(pElf32_Phdr->p_flags))
        map = add_map(map, pElf32_Phdr->p_vaddr, (Elf32_Addr)(pElf32_Phdr->p_vaddr + pElf32_Phdr->p_memsz));
      pElf32_Phdr++;
    }
  pElf32_Phdr -= x;

  return map;
}

/* Check if phdr have a READ/EXEC bit */
int check_maps(t_map *read_maps, Elf32_Addr addr)
{
  for (; read_maps != NULL; read_maps = read_maps->next)
    if (addr >= read_maps->addr_start && addr <= read_maps->addr_end)
      return TRUE;

  return FALSE;
}
