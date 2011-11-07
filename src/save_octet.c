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

t_char_importsc *add_char_importsc(t_char_importsc *old_element, char octet, Elf32_Addr addr)
{
  t_char_importsc *new_element;

  new_element = xmalloc(sizeof(t_char_importsc));
  new_element->addr        = addr;
  new_element->octet       = octet;
  new_element->next        = old_element;
  if (old_element != NULL)
    old_element->back = new_element;

  return (new_element);
}

void save_octet(unsigned char *data, Elf32_Addr offset)
{
  static int cpt = 0;

  if (*data == importsc_mode.opcode[cpt] && cpt != importsc_mode.size)
    {
      importsc_mode.poctet = add_char_importsc(importsc_mode.poctet, *data, offset);
      cpt++;
    }
}
