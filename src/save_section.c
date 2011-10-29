/*
** RopGadget - Dev v3.3
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** http://shell-storm.org
** 2011-10-29
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

static t_list_section *add_section(t_list_section *old_element, char *name, Elf32_Addr addr, Elf32_Off offset, size_t size)
{
  t_list_section *new_element;

  new_element = xmalloc(sizeof(t_list_section));

  new_element->name_section = name;
  new_element->addr = addr;
  new_element->offset = offset;
  new_element->size = size;
  new_element->next = old_element;

  return (new_element);
}

static void save_info_section_ropmaker(void)
{
  t_list_section *tmp;

  tmp = list_section;
  while (tmp)
    {
      if (!strcmp(tmp->name_section, ".data"))    /* for the ropmaker */
        Addr_sData = tmp->addr;

      if (!strcmp(tmp->name_section, ".got"))     /* for the ropmaker -importsc */
        {
          Addr_sGot = tmp->addr;
          importsc_mode.gotsize = tmp->size;
        }
      if (!strcmp(tmp->name_section, ".got.plt")) /* for the ropmaker -importsc */
        importsc_mode.gotpltsize = tmp->size;

      tmp = tmp->next;
    }
}

void save_section(void)
{
  int  x = 0;
  char *ptrNameSection;
  list_section = NULL;

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

  while (x != pElf_Header->e_shnum)
  {
    list_section = add_section(list_section,
                               (ptrNameSection + pElf32_Shdr->sh_name),
                               pElf32_Shdr->sh_addr,
                               pElf32_Shdr->sh_offset,
                               pElf32_Shdr->sh_size);
    x++;
    pElf32_Shdr++;
  }
  save_info_section_ropmaker();
  pElf32_Shdr -= x;
}

