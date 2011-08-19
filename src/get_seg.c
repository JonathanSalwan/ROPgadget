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

char *get_seg(Elf32_Word seg)
{
  if (seg == 0)
    return ("NULL");
  else if (seg == 1)
    return ("LOAD");
  else if (seg == 2)
    return ("DYNAMIC");
  else if (seg == 3)
    return ("INTERP");
  else if (seg == 4)
    return ("NOTE");
  else if (seg == 5)
    return ("SHLIB");
  else if (seg == 6)
    return ("PHDR");
  else if (seg == 7)
    return ("TLS");
  else if (seg == 8)
    return ("NUM");
  else if (seg == 0x60000000)
    return ("LOOS");
  else if (seg == 0x6fffffff)
    return ("HIOS");
  else if (seg == 0x70000000)
    return ("LOPROC");
  else if (seg == 0x7fffffff)
    return ("HIPROC");
  else if (seg == 0x6474e550)
    return ("EH_FRAME");
  else if (seg == 0x6474e551)
    return ("STACK");
  else if (seg == 0x6474e552)
    return ("RELRO");
  else if (seg == 0x65041580)
    return ("PAX_FLAGS");
  else
    return ("ERROR");
}
