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

int check_interrogation(char *str)
{
  return !!strchr(str, '?') || !!strchr(str, '#');
}

static int calc_pos_charany(char *value, int size)
{
  int i;

  for (i = 0; i < size; i++)
    if (value[i] == '?' || value[i] == '#')
      return i;
  return -1;
}

static char *ret_instruction_interrogation(char *offset, char *instruction, char *value, int size)
{
  char *gad;
  char operande[8] = {0};
  unsigned char *offset_interrogation;
  int i;
  int ret;

  ret = calc_pos_charany(value, size);
  if (ret == -1)
    return ("Error instruction without '?'\n");
  gad = xmalloc((strlen(instruction) + 64) * sizeof(char));
  memset(gad, 0x00, (strlen(instruction) + 64) * sizeof(char));
  offset_interrogation = (unsigned char *)(offset + ret);

  for (i = 0; *instruction != '\0'; instruction++, i++)
    {
      if (*instruction == '?')
        {
          sprintf(operande, "%.2x", *offset_interrogation);
          strcat(gad, operande);
          i++;
        }
      else
        gad[i] = *instruction;
    }

  return gad;
}

static char *ret_instruction_diese(char *offset, char *instruction, char *value, int size)
{
  char *gad;
  unsigned char *offset_diese;
  unsigned int operande;
  char tmp[12] = {0} ;
  int i;
  int ret;

  ret = calc_pos_charany(value, size);
  if (ret == -1)
    return ("Error instruction without '#'\n");
  gad = xmalloc((strlen(instruction) + 64) * sizeof(char));
  memset(gad, 0x00, (strlen(instruction) + 64) * sizeof(char));
  offset_diese = (unsigned char *)(offset + ret);

  for (i = 0; *instruction != '\0'; instruction++, i++)
    {
      if (*instruction == '#')
        {
          operande = offset_diese[3] << 24;
          operande += offset_diese[2] << 16;
          operande += offset_diese[1] << 8;
          operande += offset_diese[0];
          sprintf(tmp, "%.8x", operande);
          strcat(gad, tmp);
          i += strlen(tmp);
        }
      else
        gad[i] = *instruction;
    }

  return gad;
}

int check_if_varop_was_printed(char *instruction)
{
  t_list_inst *tmp;

  for (tmp = pVarop; tmp != NULL; tmp = tmp->next)
    if (!strcmp(tmp->instruction, instruction))
      return 1;

  return 0;
}

static int interrogation_or_diese(char *instruction)
{
  for (; *instruction != '\0'; instruction++)
    if (*instruction == '?')
      return 1;
    else if (*instruction == '#')
      return 2;

  return 0;
}

char *ret_instruction(char *offset, char *instruction, char *value, int size)
{
  if (interrogation_or_diese(instruction) == 2)
    return ret_instruction_diese(offset, instruction, value, size);
  else
    return ret_instruction_interrogation(offset, instruction, value, size);
}

