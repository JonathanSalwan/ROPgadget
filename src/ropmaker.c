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

/*
** match() is used in search_instruction() for match any reg:
** ex => %e?x match with %eax, %ebx, %ecx, %edx
*/
int match(const char *s1, const char *s2, size_t n)
{
  int i = 0;

  if (strlen(s1) < n)
    return (1);
  start:
  while (s1[i] != '\0' && s2[i] != '\0' && n != 0)
    {
      if (s2[i] == '?' || s2[i] == '#')
        {
          i++;
          goto start;
        }
      if (s1[i] != s2[i])
        return (1);
      i++;
      n--;
    }
  return (0);
}

/* check if instruction was found */
int check_gadget_if_exist(char *instruction)
{
  int i = 0;

  while (pGadgets[i].instruction != NULL)
    {
      if (!strcmp(pGadgets[i].instruction, instruction) && pGadgets[i].flag == 1)
        return (TRUE);
      i++;
    }
  return (FALSE);
}

/* check if instruction was match and return addr */
Elf32_Addr search_instruction(char *instruction)
{
  char  *p;
  int   i = 0;

  while (pGadgets[i].instruction != NULL)
    {
      p = pGadgets[i].instruction;
      while (*p != 0)
        {
          if (!match(p, instruction, strlen(instruction)) && pGadgets[i].flag == 1)
            return (pGadgets[i].addr);
          p++;
        }
      i++;
    }
  return (0);
}

/* returns the gadget since addr */
char *get_gadget_since_addr(Elf32_Addr addr)
{
  int i = 0;

  while (pGadgets[i].instruction != NULL)
    {
      if (pGadgets[i].addr == addr && pGadgets[i].flag == 1)
        return (pGadgets[i].instruction);
      i++;
    }
  return ("Error");
}

void ropmaker(void)
{
  if (importsc_mode.flag == 0)
    {
      combo_ropmaker1();
      combo_ropmaker2();
    }
  else if (importsc_mode.flag == 1)
    combo_ropmaker_importsc();
}
