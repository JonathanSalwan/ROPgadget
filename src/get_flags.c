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

char *get_flags(Elf32_Word flags)
{
  if (flags == 0)
    return ("---");
  else if (flags == 1)
    return ("--x");
  else if (flags == 2)
    return ("-w-");
  else if (flags == 3)
    return ("-wx");
  else if (flags == 4)
    return ("r--");
  else if (flags == 5)
    return ("r-x");
  else if (flags == 6)
    return ("rw-");
  else if (flags == 7)
    return ("rwx");
  else
    return ("Err");
}
