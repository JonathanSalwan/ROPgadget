/*
** RopGadget
** Allan Wirth - http://allanwirth.com/
** Jonathan Salwan - http://twitter.com/JonathanSalwan
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

void make_opcode(char *str, t_opcode *op)
{
  unsigned char *ptr;
  size_t size, i;

  size = strlen(str);
  ptr = xmalloc(size * sizeof(char));
  memset(ptr, 0x00, size * sizeof(char));

  for (i = 0; *str; i++, str += 2)
    {
      if (str[0] != '\\' || str[1] != 'x')
        {
          eprintf("%sSyntax error%s: Bad separator\n", RED, ENDC);
          eprintf("              Please respect this syntax: \\xcd\\x80\n");
          exit(EXIT_FAILURE);
        }
      str += 2;
      if (!isxdigit(str[0]) || !isxdigit(str[1]))
        {
          eprintf("%sOpcode error%s: No hexa byte\n", RED, ENDC);;
          exit(EXIT_FAILURE);
        }
      ptr[i] = (unsigned char)strtol(str, NULL, 16);
    }
  op->size = i;
  op->opcode = ptr;
}

void print_opcode(void)
{
  size_t i;

  for (i = 0; i != opcode_mode.size; i++)
    uprintf("\\x%.2x", opcode_mode.opcode[i]);

  if (asm_mode.flag == 1)
    uprintf("%s %s<==>%s %s%s", ENDC, YELLOW, ENDC, BLUE, asm_mode.string);
}
