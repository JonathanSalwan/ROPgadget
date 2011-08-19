/*
** RopGadget - Release v3.0
** Jonathan Salwan - http://shell-storm.org - http://twitter.com/shell_storm
** 2011-08-01
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

/* gadget necessary for the combo 2 */
t_ropmaker tab_combo_ropsh2[] =
{
  {"sysenter"},
  {"inc %eax"},
  {"xor %eax,%eax"},
  {"mov %e?x,(%e?x)"},
  {"pop %eax"},
  {"pop %ebx"},
  {"pop %ecx"},
  {"pop %edx"},
  {"pop %ebp"},
  {NULL}
};

void combo_ropmaker2(void)
{
  int i = 0;
  Elf32_Addr addr;
  t_makecode *list_ins = NULL;

  /* check if the combo 2 is possible */
  while (tab_combo_ropsh2[i].instruction)
    {
      if (search_instruction(tab_combo_ropsh2[i].instruction) == 0)
        {
          fprintf(stderr, "[%s-%s] Combo 2 was not found (%sMiss%s: %s)\n", RED, ENDC, RED, ENDC, tab_combo_ropsh2[i].instruction);
          return ;
        }
      i++;
    }

  fprintf(stdout, "[%s+%s] Combo 2 was found - Possible with the following gadgets. (execve)\n", GREEN, ENDC);
  i = 0;
  while (tab_combo_ropsh2[i].instruction)
    {
      addr = search_instruction(tab_combo_ropsh2[i].instruction);
      if (addr)
        {
          fprintf(stdout, "\t- %s0x%.8x%s => %s%s%s\n", RED, addr, ENDC, GREEN, get_gadget_since_addr(addr), ENDC);
          list_ins = add_element(list_ins, get_gadget_since_addr(addr), addr);
        }
      i++;
    }
  fprintf(stdout, "\t- %s0x%.8x%s => %s.data Addr%s\n", RED, Addr_sData, ENDC, YELLOW, ENDC);

  /* make a python code */
  makecode(list_ins);
}
