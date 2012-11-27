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

void print_opcode(void)
{
  int i;

  for (i = 0; i != opcode_mode.size; i++)
    fprintf(stdout, "\\x%.2x", opcode_mode.opcode[i]);

  if (asm_mode.flag == 1)
    fprintf(stdout, "%s %s<==>%s %s%s", ENDC, YELLOW, ENDC, BLUE, asm_mode.argument);
}

int search_opcode(const char *s1, const char *s2, size_t n)
{
  size_t i;
  for (i = 0; i < n; i++)
    if (s1[i] != s2[i] && !(s2[i] == '?' || s2[i] == '_'))
      return 1;

  return 0;
}
