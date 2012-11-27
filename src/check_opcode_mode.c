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

int size_opcode(char *str)
{
  int cpt;

  for (cpt = 0; *str != '\0'; str++)
    if (*str == '\\')
      cpt++;

  if (cpt == 0)
    {
      fprintf(stderr, "%sSyntax%s: -opcode <opcode>\n", RED, ENDC);
      fprintf(stderr, "%sEx%s:     -opcode \"\\xcd\\x80\"\n", RED, ENDC);
      exit(EXIT_FAILURE);
    }
  return cpt;
}

static void check_char(char c)
{
  if (isxdigit(c))
    return ;

  fprintf(stderr, "%sOpcode error%s: No hexa byte\n", RED, ENDC);;
  exit(EXIT_FAILURE);
}

void make_opcode(char *str, t_opcode *op)
{
  int i;
  unsigned char *ptr;
  int size;

  size = size_opcode(str);
  op->size = size;
  ptr = xmalloc(size * sizeof(char));
  memset(ptr, 0x00, size * sizeof(char));
  for (i = 0; i != size; i++, str += 2)
    {
      if (str[0] != '\\' || str[1] != 'x')
        {
          fprintf(stderr, "%sSyntax error%s: Bad separator\n", RED, ENDC);
          fprintf(stderr, "              Please respect this syntax: \\xcd\\x80\n");
          exit(EXIT_FAILURE);
        }
      str += 2;
      check_char(str[0]);
      check_char(str[1]);
      ptr[i] = strtol(str, NULL, 16);
    }
  op->opcode = ptr;
}
