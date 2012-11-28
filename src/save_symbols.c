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

static t_list_symbols *add_symbols(t_list_symbols *old_element, char *name, uint32_t st_name, Elf32_Addr value, uint32_t size, unsigned char info, unsigned char other, uint16_t shndx)
{
  t_list_symbols *new_element;

  new_element = xmalloc(sizeof(t_list_symbols));
  new_element->name     = name;
  new_element->st_name  = st_name;
  new_element->st_value = value;
  new_element->st_size  = size;
  new_element->st_info  = info;
  new_element->st_other = other;
  new_element->st_shndx = shndx;
  new_element->next = old_element;
  if (old_element != NULL)
    old_element->back = new_element;

  return (new_element);
}

void save_symbols(unsigned char *data)
{
  char *strtab = (char *)data;
  unsigned char *data_end = data;
  Elf32_Sym *sym;

  t_list_section *strtab_s = get_section(".strtab");
  t_list_section *symtab_s = get_section(".symtab");

  list_symbols = NULL;
  if (strtab_s == NULL) /* check if symbols exist */
    return ;

  data_end += symtab_s->offset + symtab_s->size;
  data += symtab_s->offset;
  strtab += strtab_s->offset;

  while (data < data_end)
    {
      sym = (Elf32_Sym *)data;
      list_symbols = add_symbols(list_symbols, (strtab + sym->st_name),  sym->st_name, sym->st_value, sym->st_size, sym->st_info, sym->st_other, sym->st_shndx);
      data += symtab_s->entsize;
    }
  /* go to top of the list */
  while (list_symbols->next != NULL)
    list_symbols = list_symbols->next;
}
