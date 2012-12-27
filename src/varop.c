/*
** RopGadget - Release v3.4.2
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** Allan Wirth - http://allanwirth.com/
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

int check_interrogation(const char *str)
{
  return !!strchr(str, '?') || !!strchr(str, '#');
}

static int calc_pos_charany(const char *value, int size)
{
  int i;

  for (i = 0; i < size; i++)
    if (value[i] == '?' || value[i] == '#')
      return i;
  return -1;
}

int check_if_varop_was_printed(const char *instruction)
{
  t_list_inst *tmp;

  for (tmp = pVarop; tmp != NULL; tmp = tmp->next)
    if (!strcmp(tmp->instruction, instruction))
      return 1;

  return 0;
}

char *ret_instruction(const unsigned char *offset, const char *instruction,
const char *value, int size)
{
  char *gad;
  const unsigned char *offset_wildcard;
  unsigned int value_offset;
  char tmp[16] = {0};
  unsigned int operande;
  int i;
  int ret;

  gad = xmalloc((strlen(instruction) + 64) * sizeof(char));
  memset(gad, 0x00, (strlen(instruction) + 64) * sizeof(char));
  value_offset = 0;

  for (i = 0; *instruction != '\0'; instruction++, i++)
    {
      if (*instruction == '?' || *instruction == '#')
        {
          ret = calc_pos_charany(value+value_offset, size-value_offset);
          if (ret == -1)
            return ("Error instruction without '?' or '#'\n");
          value_offset += ret;
          offset_wildcard = offset + value_offset;
          if (*instruction == '?')
            {
              sprintf(tmp, "%.2x", *offset_wildcard);
              value_offset += 1;
            }
          else
            {
              operande = offset_wildcard[3] << 24;
              operande += offset_wildcard[2] << 16;
              operande += offset_wildcard[1] << 8;
              operande += offset_wildcard[0];
              sprintf(tmp, "%.8x", operande);
              value_offset += 4;
            }
          strcat(gad, tmp);
          i += strlen(tmp);
        }
      else
        gad[i] = *instruction;
    }

  return gad;
}

char getreg(const char *str, int i)
{
  for (; *str !='\0'; str++)
    if (i == 1 && *str == ',' && *(str+1) == '(')
      return (*(str-2));
    else if (i == 2 && *str == ',' && *(str+1) == '(')
      return (*(str+4));
    else if (i == 3 && *str == ')' && *(str+1) == ',')
      return (*(str+4));

  return 0;
}
