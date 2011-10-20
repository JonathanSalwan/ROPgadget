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

#include "ropgadget.h"

static int pose_var(char *str)
{
  int i = 0;
  int size;

  size = stringmode.size;
  while (size != 0 && str[i] != '?')
    {
      i++;
      size--;
    }

  return (i);
}

static int check_var(char *str)
{
  int size;

  size = stringmode.size;
  while (size != 0)
    {
      if (*str == '?')
        return (1);
      str++;
      size--;
    }
  return (0);
}

void print_real_string(char *str)
{
  int size;

  size = stringmode.size;
  while (size != 0)
    {
      if (*str >= 0x20 && *str <= 0x7e)
        fprintf(stdout, "%c", *str);
      else
        fprintf(stdout, "\\x%.2x", (unsigned char)(*(str)));
      str++;
      size--;
    }
}

char *real_string_stringmode(char *base_string, unsigned char *data)
{
  char *real_string;
  int  size;
  int  i = 0;

  size = (strlen(base_string) + 1);
  real_string = xmalloc(size * sizeof(char));
  strncpy(real_string, base_string, size);

  while (check_var(real_string) == 1)
    {
      i = pose_var(real_string);
      real_string[i] = data[i];
    }

  return (real_string);
}
