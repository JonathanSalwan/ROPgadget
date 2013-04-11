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

void print_real_string(unsigned char *str)
{
  size_t l;
  size_t i;

  l = strlen(stringmode.string);
  for (i = 0; i < l; i++)
    uprintf((str[i] >= 0x20 && str[i] <= 0x7e)?"%c":"\\x%.2x", str[i]);
}

unsigned char *real_string_stringmode(char *base_string, unsigned char *data)
{
  unsigned char *real_string;
  size_t i;

  real_string = xmalloc((strlen(base_string) + 1) * sizeof(char));
  /* Loop through ?s and set them to the same index in data */
  for (i = 0; base_string[i]; i++)
    if (base_string[i] == '?')
      real_string[i] = data[i];
    else
      real_string[i] = (unsigned char)base_string[i];
  real_string[i] = '\0';

  return real_string;
}
