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

#define UNIX     pElf_Header->e_ident[EI_OSABI] == ELFOSABI_NONE
#define LINUX    pElf_Header->e_ident[EI_OSABI] == ELFOSABI_LINUX
#define FREEBSD  pElf_Header->e_ident[EI_OSABI] == ELFOSABI_FREEBSD
#define ELF_F    pElf_Header->e_ident[EI_CLASS] == ELFCLASS32
#define PROC     pElf_Header->e_machine == EM_386

void search_gadgets(unsigned char *data, unsigned int size_data)
{
  t_maps_exec *maps_exec;

  if (check_elf_format(data) == -1)
    no_elf_format();
  if (check_arch_supported() == -1)
    no_arch_supported();

  maps_exec = display_info_header();
  fprintf(stdout, "%sGadgets informations\n", YELLOW);
  fprintf(stdout, "============================================================%s\n", ENDC);

  /* Linux/x86-32bits & FreeBSD/x86-32bits*/
  if (ELF_F && (UNIX || LINUX || FREEBSD) && PROC)
    x8632(data, size_data, maps_exec);

  fprintf(stdout, "\n\n%sPossible combinations.\n", YELLOW);
  fprintf(stdout, "============================================================%s\n\n", ENDC);

  ropmaker();

  free_add_maps_exec(maps_exec);
}
