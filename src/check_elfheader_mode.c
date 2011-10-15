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

void check_elfheader_mode(char **argv)
{
  int i = 0;

  while (argv[i] != NULL)
    {
      if (!strcmp(argv[i], "-elfheader") && flag_elfheader == 0)
        {
          fprintf(stdout, "%sELF Header\n", YELLOW);
          fprintf(stdout, "============================================================%s\n\n", ENDC);
          fprintf(stdout, "entry        %s0x%.8x%s\n",	      RED, pElf_Header->e_entry, ENDC);
          fprintf(stdout, "phoff        %s0x%.8x%s\n",        RED, pElf_Header->e_phoff, ENDC);
          fprintf(stdout, "shoff        %s0x%.8x%s\n",        RED, pElf_Header->e_shoff, ENDC);
          fprintf(stdout, "flags        %s0x%.8x%s\n",        RED, pElf_Header->e_flags, ENDC);
          fprintf(stdout, "ehsize       %s0x%.8x (%d)%s\n",   RED, pElf_Header->e_ehsize, pElf_Header->e_ehsize, ENDC);
          fprintf(stdout, "phentsize    %s0x%.8x (%d)%s\n",   RED, pElf_Header->e_phentsize, pElf_Header->e_phentsize, ENDC);
          fprintf(stdout, "phnum        %s0x%.8x (%d)%s\n",   RED, pElf_Header->e_phnum, pElf_Header->e_phnum,ENDC);
          fprintf(stdout, "shentsize    %s0x%.8x (%d)%s\n",   RED, pElf_Header->e_shentsize, pElf_Header->e_shentsize, ENDC);
          fprintf(stdout, "shnum        %s0x%.8x (%d)%s\n",   RED, pElf_Header->e_shnum, pElf_Header->e_shnum,ENDC);
          fprintf(stdout, "shstrndx     %s0x%.8x (%d)%s\n\n\n", RED, pElf_Header->e_shstrndx,  pElf_Header->e_shstrndx,ENDC);
          flag_elfheader = 1;
        }
      i++;
    }
}
