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

t_char_importsc *add_char_importsc(t_char_importsc *old_element, char octet, Elf32_Addr addr)
{
  t_char_importsc *new_element;

  new_element = malloc(sizeof(t_char_importsc));
  if (new_element == NULL)
    exit(EXIT_FAILURE);
  new_element->addr        = addr;
  new_element->octet       = octet;
  new_element->next        = old_element;
  if (old_element != NULL)
    old_element->back = new_element;

  return (new_element);
}

void save_octet(unsigned char *data, Elf32_Addr offset)
{
  static int cpt = 0;

  if (*data == importsc_mode.opcode[cpt] && cpt != importsc_mode.size)
    {
      importsc_mode.poctet = add_char_importsc(importsc_mode.poctet, *data, offset);
      cpt++;
    }
}
