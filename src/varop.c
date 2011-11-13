/*
** RopGadget - Release v3.3.1
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** http://shell-storm.org
** 2011-11-13
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

/* linked list for variable operation */
t_varop *add_element_varop(t_varop *old_element, char *instruction, Elf32_Addr offset)
{
  t_varop *new_element;

  new_element = xmalloc(sizeof(t_varop));
  new_element->instruction = instruction;
  new_element->addr        = offset;
  new_element->next        = old_element;

  return (new_element);
}

/* free linked list (variable opcode) */
void free_var_opcode(t_varop *element)
{
  t_varop *tmp;

  while(element)
    {
      tmp = element;
      element = element->next;
      free(tmp->instruction);
      free(tmp);
    }
}

int check_interrogation(char *str)
{
  while (*str != '\0')
    {
      if (*str == '?' || *str == '_')
        return (1);
      str++;
    }
  return (0);
}

int calc_pos_charany(char *value, int size)
{
  int i = 0;

  while (i < size)
    {
      if (*value == '?' || *value == '_')
        return (i);
      i++;
      value++;
    }
  return (-1);
}

char *ret_instruction_interrogation(char *offset, char *instruction, char *value, int size)
{
  char *gad;
  char operande[8] = {0};
  unsigned char *offset_interrogation;
  int i = 0;
  int ret;

  ret = calc_pos_charany(value, size);
  if (ret == -1)
    return ("Error instruction with '?'\n");
  gad = xmalloc((strlen(instruction) + 64) * sizeof(char));
  memset(gad, 0x00, (strlen(instruction) + 64) * sizeof(char));
  offset_interrogation = (unsigned char *)(offset + ret);

  while (*instruction != '\0')
    {
      if (*instruction == '?')
        {
          sprintf(operande, "%.2x", *offset_interrogation);
          strcat(gad, operande);
          i++;
        }
      else
        gad[i] = *instruction;
      instruction++;
      i++;
    }
  return (gad);
}

char *ret_instruction_diese(char *offset, char *instruction, char *value, int size)
{
  char *gad;
  unsigned char *offset_diese;
  unsigned char operande[4] = {0};
  char tmp[12] = {0} ;
  int i = 0;
  int ret;

  ret = calc_pos_charany(value, size);
  if (ret == -1)
    return ("Error instruction with '_'\n");
  gad = xmalloc((strlen(instruction) + 64) * sizeof(char));
  memset(gad, 0x00, (strlen(instruction) + 64) * sizeof(char));
  offset_diese = (unsigned char *)(offset + ret);

  while (*instruction != '\0')
    {
      if (*instruction == '_')
        {
          operande[0] = *(offset_diese + 0);
          operande[1] = *(offset_diese + 1);
          operande[2] = *(offset_diese + 2);
          operande[3] = *(offset_diese + 3);
          sprintf(tmp, "%.8x", *(unsigned int *)operande);
          strcat(gad, tmp);
          i += 7;
        }
      else
        gad[i] = *instruction;
      instruction++;
      i++;
    }
  return (gad);
}

int check_if_varop_was_printed(char *instruction)
{
  t_varop *tmp;

  tmp = pVarop;
  while (tmp != NULL)
    {
      if (!strcmp(tmp->instruction, instruction))
        return (1);
      tmp = tmp->next;
    }
  return (0);
}

int interrogation_or_diese(char *instruction)
{
  while (*instruction != '\0')
    {
      if (*instruction == '?')
        return (1);
      else if (*instruction == '_')
        return (2);
      instruction++;
    }
  return (0);
}
