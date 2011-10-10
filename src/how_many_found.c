/*
** RopGadget - Release v3.2
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** http://shell-storm.org
** 2011-10-10
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
  if (opcode_mode.flag != 1)
    fprintf(stdout, "\nUnique gadgets found: %s%d%s\n", YELLOW, NbGadFound, ENDC);
  else
    fprintf(stdout, "\nTotal opcodes found: %s%d%s\n", YELLOW, NbTotalGadFound, ENDC);
}
