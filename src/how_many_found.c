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

void how_many_found()
{
  int i   = 0;
  int val = 0;

  while (pGadgets[i].instruction)
    {
      if (pGadgets[i].flag == 1)
        val++;
      i++;
    }

  fprintf(stdout, "\nTotal gadgets: %s%d/%d%s\n", YELLOW, val, i, ENDC);
}
