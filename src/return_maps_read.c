/*
** RopGadget - Dev v3.3
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** http://shell-storm.org
** 2011-10-18
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

/* function for add a new element in linked list | save a read maps */
static t_maps_read *add_maps_read(t_maps_read *old_element, Elf32_Addr addr_start, Elf32_Addr addr_end)
{
  t_maps_read *new_element;

  new_element = malloc(sizeof(t_maps_read));
  if (new_element == NULL)
    exit(EXIT_FAILURE);
  new_element->addr_start = addr_start;
  new_element->addr_end   = addr_end;
  new_element->next       = old_element;

  return (new_element);
}

/* free linked list */
void free_add_maps_read(t_maps_read *element)
{
  t_maps_read *tmp;

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
  if (flag == 2 || flag == 4 || flag == 5 || flag == 6)
    return (TRUE);
  else
    return (FALSE);
}


/* return linked list with maps read segment */
t_maps_read *return_maps_read(void)
{
  int  x = 0;
  t_maps_read *maps_read;

  maps_read = NULL;
  while (x != pElf_Header->e_phnum)
    {
      if (check_read_flag(pElf32_Phdr->p_flags) == TRUE)
        maps_read = add_maps_read(maps_read, pElf32_Phdr->p_vaddr, (Elf32_Addr)(pElf32_Phdr->p_vaddr + pElf32_Phdr->p_memsz));
      x++;
      pElf32_Phdr++;
    }
  pElf32_Phdr -= x;

  return (maps_read);
}
