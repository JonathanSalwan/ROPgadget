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

#include <stdio.h>
#include "ropgadget.h"

void no_elf_format(void)
{
  fprintf(stderr, "Error: No elf format\n");
  exit(EXIT_FAILURE);
}

int check_elf_format(unsigned char *data)
{
  if (!strncmp((const char *)data, MAGIC_ELF, 4))
    return (0);
  return (-1);
}
