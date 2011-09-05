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

#include <stdio.h>
#include "ropgadget.h"

void no_elf_format(void)
{
  fprintf(stderr, "Error: No elf format\n");
  exit(EXIT_FAILURE);
}

int check_elf_format(unsigned char *data)
{
  if (!strncmp((const char *)data, MAGIC_ELF, 4))
    return (0);
  return (-1);
}
