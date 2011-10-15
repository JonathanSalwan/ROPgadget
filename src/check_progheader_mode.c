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

void check_progheader_mode(char **argv)
{
  int i = 0;
  int  x = 0;

  while (argv[i] != NULL)
    {
      if (!strcmp(argv[i], "-progheader") && flag_progheader == 0)
        {
          fprintf(stdout, "%sProgram Header\n", YELLOW);
          fprintf(stdout, "============================================================%s\n\n", ENDC);
          while (x != pElf_Header->e_phnum)
            {
              fprintf(stdout, "%s%s%s\n", YELLOW, get_seg(pElf32_Phdr->p_type), ENDC);
              fprintf(stdout, "\toffset ");
              fprintf(stdout, "%s0x%.8x%s ",  RED, pElf32_Phdr->p_offset, ENDC);
              fprintf(stdout, "vaddr ");
              fprintf(stdout, "%s0x%.8x%s ",  RED, pElf32_Phdr->p_vaddr, ENDC);
              fprintf(stdout, "paddr ");
              fprintf(stdout, "%s0x%.8x%s\n", RED, pElf32_Phdr->p_paddr, ENDC);
              fprintf(stdout, "\tfilesz ");
              fprintf(stdout, "%s0x%.8x%s ",  RED, pElf32_Phdr->p_filesz, ENDC);
              fprintf(stdout, "memsz ");
              fprintf(stdout, "%s0x%.8x%s ",  RED, pElf32_Phdr->p_memsz, ENDC);
              fprintf(stdout, "flags ");
              fprintf(stdout, "%s%s%s\n",   RED, get_flags(pElf32_Phdr->p_flags), ENDC);
              x++;
              pElf32_Phdr++;
            }
          pElf32_Phdr -= x;
          flag_progheader = 1;
          fprintf(stdout, "\n\n");
        }
      i++;
    }
}
