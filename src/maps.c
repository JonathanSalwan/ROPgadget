/*
** RopGadgetX - Release v1.0.0
** Allan Wirth - http://allanwirth.com/
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** 2012-1-4
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

/* Set mapmode */
size_t set_cpt_if_mapmode(size_t cpt, const t_binary *bin)
{
  return (mapmode.flag == 0)?cpt:(mapmode.addr_start - bin->base_addr);
}

size_t check_end_mapmode(size_t cpt, const t_binary *bin)
{
  return (mapmode.flag && cpt + bin->base_addr > mapmode.addr_end);
}

/* Check if phdr have a READ/EXEC bit */
int check_maps(t_map *read_maps, Address addr)
{
  for (; read_maps != NULL; read_maps = read_maps->next)
    if (addr >= read_maps->addr_start && addr <= read_maps->addr_end)
      return TRUE;

  return FALSE;
}

void map_parse(char *str, const t_binary *bin)
{
  mapmode.addr_start = (Address)strtol(str, NULL, 16);

  while (*str != '-' && *str != '\0')
    str++;
  if (*str == '-')
    str++;

  mapmode.addr_end = (Address)strtol(str, NULL, 16);

  if (mapmode.addr_start < bin->base_addr || mapmode.addr_end > bin->end_addr || mapmode.addr_start > mapmode.addr_end)
    {
      eprintf("%sError value for -map option%s\n", RED, ENDC);
      eprintf("%sMap addr need value between " ADDR_FORMAT " and " ADDR_FORMAT "\n%s", RED, ADDR_WIDTH, bin->base_addr, ADDR_WIDTH, bin->end_addr, ENDC);
      exit(EXIT_FAILURE);
    }
}
