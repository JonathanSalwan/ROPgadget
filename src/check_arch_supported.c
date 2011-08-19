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

#include <stdio.h>
#include "ropgadget.h"

void no_arch_supported(void)
{
  fprintf(stderr, "Error: Architecture isn't supported\n");
  exit(EXIT_FAILURE);
}

int check_arch_supported(void)
{
  /* supported: - Linux/x86-32bits */
  if (pElf_Header->e_ident[EI_CLASS] == ELFCLASS32 && pElf_Header->e_ident[EI_OSABI] == ELFOSABI_NONE && pElf_Header->e_machine == EM_386)
    return (0);
  /* supported: - FreeBSD/x86-32bits */
  if (pElf_Header->e_ident[EI_CLASS] == ELFCLASS32 && pElf_Header->e_ident[EI_OSABI] == ELFOSABI_FREEBSD && pElf_Header->e_machine == EM_386)
    return (0);
  return (-1);
}
