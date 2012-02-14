/*
** RopGadget - Release v3.3.2
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** http://shell-storm.org
** 2012-02-14
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

static void check_char(char c)
{
  if (c >= '0' && c <= '9')
    return ;
  else if (c >= 'a' && c <= 'f')
    return ;
  else if (c >= 'A' && c <= 'F')
    return ;

  fprintf(stderr, "%sOpcode error%s: No hexa byte\n", RED, ENDC);
  exit(EXIT_FAILURE);
}

static void make_opcode(char *str)
{
  int i = 0;
  unsigned char *ptr;
  int size;

  size = size_opcode(str);
  importsc_mode.size = size;
  ptr = xmalloc(size * sizeof(char));
  memset(ptr, 0x00, size * sizeof(char));
  while (i != size)
    {
      if (*str != '\\' && *str != 'x')
        {
          fprintf(stderr, "%sSyntax error%s: Bad separator\n", RED, ENDC);
          fprintf(stderr, "              Please respect this syntax: \\xcd\\x80\n");
          exit(EXIT_FAILURE);
        }
      while (*str == '\\' || *str == 'x')
        str++;
      check_char(*str);
      check_char(*(str + 1));
      ptr[i] = strtol(str, NULL, 16);
      i++;
      str += 2;
    }
  importsc_mode.opcode = ptr;
}

void check_importsc_mode(char **argv)
{
  int i = 0;

  importsc_mode.flag = 0;
  while (argv[i] != NULL)
    {
      if (!strcmp(argv[i], "-importsc"))
        {
          if (argv[i + 1] != NULL && argv[i + 1][0] != '\0')
            {
              importsc_mode.argument = argv[i + 1];
              importsc_mode.flag = 1;
              make_opcode(argv[i + 1]);
            }
          else
            {
              fprintf(stderr, "%sSyntax%s: -importsc <shellcode>\n", RED, ENDC);
              fprintf(stderr, "%sEx%s:     -importsc \"\\x6a\\x02\\x58\\xcd\\x80\\xeb\\xf9\"\n", RED, ENDC);
              exit(EXIT_FAILURE);
            }
        }
      i++;
    }
}
