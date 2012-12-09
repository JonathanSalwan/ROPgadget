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

static t_list_section *add_section(t_list_section *old_element, char *name, Address addr, Elf32_Off offset, size_t size, int entsize)
{
  t_list_section *new_element;

  new_element = xmalloc(sizeof(t_list_section));

  new_element->name_section = name;
  new_element->addr = addr;
  new_element->offset = offset;
  new_element->size = size;
  new_element->entsize = entsize;
  new_element->next = old_element;

  return (new_element);
}

/* returns section size by name */
t_list_section *get_section(char *name)
{
  t_list_section *tmp;

  for (tmp = list_section; tmp != NULL; tmp = tmp->next)
    if (!strcmp(tmp->name_section, name))
      return tmp;

  return NULL;
}

static void save_info_section_ropmaker(void)
{
  t_list_section *data = get_section(".data");
  t_list_section *got = get_section(".got");
  t_list_section *gotplt = get_section(".got.plt");
  Addr_sData                = data?data->addr:0;
  Addr_sGot                 = got?got->addr:0;
  importsc_mode.gotsize     = got?got->size:0;
  importsc_mode.gotpltsize  = gotplt?gotplt->size:0;

  if (((char *)&Addr_sData)[0] == 0x00)
    Addr_sData++;
  if (((char *)&Addr_sGot)[0] == 0x00)
    Addr_sGot++;
}

#define SHDR(X, t) (containerType == CONTAINER_ELF32?((t)(a.pElf32_Shdr X)):((t)(a.pElf64_Shdr X)))
void save_section(void)
{
  Size  x = 0;
  char *ptrNameSection = NULL;
  Size shnum;
  union {
    Elf32_Shdr *pElf32_Shdr;
    Elf64_Shdr *pElf64_Shdr;
  } a;

  if (containerType == CONTAINER_ELF32)
    a.pElf32_Shdr = (Elf32_Shdr *)(filemode.data + pElf32_Header->e_shoff);
  else
    a.pElf64_Shdr = (Elf64_Shdr *)(filemode.data + pElf64_Header->e_shoff);

  list_section = NULL;
  shnum = (containerType == CONTAINER_ELF32?pElf32_Header->e_shnum:pElf64_Header->e_shnum);

  for (x = 0; x != shnum; x++, SHDR(++, void*))
    {
      if (SHDR(->sh_type, Elf64_Word) == SHT_STRTAB && SHDR(->sh_addr, Address) == 0)
        {
          ptrNameSection = (char *)pMapElf + SHDR(->sh_offset, ssize_t);
          break;
        }
    }
  SHDR( -= x, void *);

  for ( x = 0; x != shnum; x++, SHDR(++, void *))
  {
    list_section = add_section(list_section,
                               (ptrNameSection + SHDR(->sh_name, size_t)),
                               SHDR(->sh_addr, Address),
                               SHDR(->sh_offset, Offset),
                               SHDR(->sh_size, size_t),
                               SHDR(->sh_entsize, int));
  }
  save_info_section_ropmaker();
}
#undef SHDR
