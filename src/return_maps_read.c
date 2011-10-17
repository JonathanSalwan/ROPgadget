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

/* function for add a new element in linked list | save a read maps */
static t_maps_read *add_maps_read(t_maps_read *old_element, Elf32_Addr addr_start, Elf32_Addr addr_end)
{
  t_maps_read *new_element;

  new_element = malloc(sizeof(t_maps_read));
  if (new_element == NULL)
    exit(EXIT_FAILURE);
  new_element->addr_start = addr_start;
  new_element->addr_end   = addr_end;
  new_element->next       = old_element;

  return (new_element);
}

/* free linked list */
void free_add_maps_read(t_maps_read *element)
{
  t_maps_read *tmp;

  while(element)
    {
      tmp = element;
      element = element->next;
      free(tmp);
    }
}

/* check if flag have a READ BIT */
static int check_read_flag(Elf32_Word flag)
{
  if (flag == 2 || flag == 4 || flag == 5 || flag == 6)
    return (TRUE);
  else
    return (FALSE);
}


/* return linked list with maps read segment */
t_maps_read *return_maps_read(void)
{
  int  x = 0;
  t_maps_read *maps_read;

  maps_read = NULL;
  while (x != pElf_Header->e_phnum)
    {
      if (check_read_flag(pElf32_Phdr->p_flags) == TRUE)
        maps_read = add_maps_read(maps_read, pElf32_Phdr->p_vaddr, (Elf32_Addr)(pElf32_Phdr->p_vaddr + pElf32_Phdr->p_memsz));
      x++;
      pElf32_Phdr++;
    }
  pElf32_Phdr -= x;

  return (maps_read);
}
