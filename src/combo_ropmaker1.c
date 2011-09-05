/*
** RopGadget - Release v3.1
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** http://shell-storm.org
** 2011-09-05
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

/* gadget necessary for combo 1 */
t_ropmaker tab_combo_ropsh1[] =
{
  {"int $0x80"},
  {"inc %eax"},
  {"xor %eax,%eax"},
  {"mov %e?x,(%e?x)"},
  {"pop %eax"},
  {"pop %ebx"},
  {"pop %ecx"},
  {"pop %edx"},
  {NULL}
};

void combo_ropmaker1(void)
{
  int i = 0;
  int flag = 0;
  Elf32_Addr addr;
  t_makecode *list_ins = NULL;

  /* check combo 1 if possible */
  while (tab_combo_ropsh1[i].instruction)
    {
      if (search_instruction(tab_combo_ropsh1[i].instruction) == 0)
        {
          flag = 1;
          break;
        }
      i++;
    }

  if (flag == 0)
    fprintf(stdout, "[%s+%s] Combo 1 was found - Possible with the following gadgets. (execve)\n", GREEN, ENDC);
  else
    fprintf(stderr, "[%s-%s] Combo 1 was not found, missing instruction(s).\n", RED, ENDC);

  i = 0;
  while (tab_combo_ropsh1[i].instruction)
    {
      addr = search_instruction(tab_combo_ropsh1[i].instruction);
      if (addr)
        {
          fprintf(stdout, "\t- %s0x%.8x%s => %s%s%s\n", GREEN, addr, ENDC, GREEN, get_gadget_since_addr(addr), ENDC);
          if (!flag)
            list_ins = add_element(list_ins, get_gadget_since_addr(addr), addr);
        }
      else
        fprintf(stdout, "\t- %s..........%s => %s%s%s\n", RED, ENDC, RED, tab_combo_ropsh1[i].instruction, ENDC);
      i++;
    }
  fprintf(stdout, "\t- %s0x%.8x%s => %s.data Addr%s\n", GREEN, Addr_sData, ENDC, GREEN, ENDC);

  /* build a python code */
  if (!flag)
    makecode(list_ins);
}
