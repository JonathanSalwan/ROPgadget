/*
** RopGadget - Dev v3.3
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** http://shell-storm.org
** 2011-10-16
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions
** are met:
** 1. Redistributions of source code must retain the above copyright
**    notice, this list of conditions and the following disclaimer.
** 2. Redistributions in binary form must reproduce the above copyright
**    notice, this list of conditions and the following disclaimer in the
**    documentation and/or other materials provided with the distribution.
*/

#include "ropgadget.h"

/* linked list for variable operation */
t_varop *add_element_varop(t_varop *old_element, char *instruction, Elf32_Addr offset)
{
  t_varop *new_element;

  new_element = malloc(sizeof(t_varop));
  if (new_element == NULL)
    exit(EXIT_FAILURE);
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
      if (*str == '?' || *str == '#')
        return (1);
      str++;
    }
  return (0);
}

int calc_pos_charany(char *value)
{
  int i = 0;
  int size;

  size = strlen(value);
  while (i < size)
    {
      if (*value == '?' || *value == '#')
        return (i);
      i++;
      value++;
    }
  return (-1);
}

char *ret_instruction_interrogation(Elf32_Addr offset, char *instruction, char *value)
{
  char *gad;
  char operande[8] = {0};
  unsigned char *offset_interrogation;
  int i = 0;
  int ret;

  ret = calc_pos_charany(value);
  if (ret == -1)
    return ("Error instruction with '?'\n");
  gad = malloc((strlen(instruction) + 64) * sizeof(char));
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

char *ret_instruction_diese(Elf32_Addr offset, char *instruction, char *value)
{
  char *gad;
  unsigned char *offset_diese;
  unsigned char operande[4] = {0};
  char tmp[12] = {0} ;
  int i = 0;
  int ret;

  ret = calc_pos_charany(value);
  if (ret == -1)
    return ("Error instruction with '#'\n");
  gad = malloc((strlen(instruction) + 64) * sizeof(char));
  memset(gad, 0x00, (strlen(instruction) + 64) * sizeof(char));
  offset_diese = (unsigned char *)(offset + ret);

  while (*instruction != '\0')
    {
      if (*instruction == '#')
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
      else if (*instruction == '#')
        return (2);
      instruction++;
    }
  return (0);
}
