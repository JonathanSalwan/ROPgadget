/*
** RopGadget - Release v3.3.4
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** http://shell-storm.org
** 2012-06-25
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

/* Check if phdr have a READ bit */
int check_read_maps(t_maps_read *read_maps, Elf32_Addr addr)
{
  while (read_maps != NULL)
    {
      if (addr >= read_maps->addr_start && addr <= read_maps->addr_end)
        return (TRUE);
      read_maps = read_maps->next;
    }
  return (FALSE);
}
