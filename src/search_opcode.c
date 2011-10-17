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

void print_opcode(void)
{
  int i;

  i = 0;
  if (asm_mode.flag == 1)
    {
      while (i != opcode_mode.size)
        {
          fprintf(stdout, "\\x%.2x", opcode_mode.opcode[i]);
          i++;
        }
      fprintf(stdout, "%s %s<==>%s %s%s", ENDC, YELLOW, ENDC, BLUE, asm_mode.argument);
    }
  else
    {
      while (i != opcode_mode.size)
        {
          fprintf(stdout, "\\x%.2x", opcode_mode.opcode[i]);
          i++;
        }
    }
}

int search_opcode(const char *s1, const char *s2, size_t n)
{
  int i = 0;

  start:
  while (n != 0)
    {
      if (s2[i] == '?' || s2[i] == '_')
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
