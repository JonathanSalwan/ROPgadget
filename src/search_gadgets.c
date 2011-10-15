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

#define LINUX    pElf_Header->e_ident[EI_OSABI] == ELFOSABI_NONE
#define FREEBSD  pElf_Header->e_ident[EI_OSABI] == ELFOSABI_FREEBSD
#define ELF_F    pElf_Header->e_ident[EI_CLASS] == ELFCLASS32
#define PROC     pElf_Header->e_machine == EM_386

void search_gadgets(unsigned char *data, unsigned int size_data)
{
  t_maps_exec *maps_exec;

  maps_exec = return_maps_exec();
  fprintf(stdout, "%sGadgets information\n", YELLOW);
  fprintf(stdout, "============================================================%s\n", ENDC);

  /* Linux/x86-32bits & FreeBSD/x86-32bits*/
  if (ELF_F && (LINUX || FREEBSD) && PROC)
    x8632(data, size_data, maps_exec);

  if (opcode_mode.flag != 1)
    {
      fprintf(stdout, "\n\n%sPossible combinations.\n", YELLOW);
      fprintf(stdout, "============================================================%s\n\n", ENDC);

      ropmaker();
    }

  free_var_opcode(pVarop);
  free_add_maps_exec(maps_exec);
}
