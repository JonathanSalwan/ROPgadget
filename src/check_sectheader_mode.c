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

void check_sectheader_mode(char **argv)
{
  char *ptrNameSection;
  int i = 0;
  int x = 0;
  
  while (argv[i] != NULL)
    {
      if (!strcmp(argv[i], "-sectheader") && flag_sectheader == 0)
        {
          while(x != pElf_Header->e_shnum)
            {
              if (pElf32_Shdr->sh_type == SHT_STRTAB && pElf32_Shdr->sh_addr == 0)
                {
                  ptrNameSection =  (char *)pMapElf + pElf32_Shdr->sh_offset;
                  break;
                }
              x++;
              pElf32_Shdr++;
            }
          pElf32_Shdr -= x;
          x = 0;

          fprintf(stdout, "%sSection Header\n", YELLOW);
          fprintf(stdout, "============================================================%s\n\n", ENDC);
          fprintf(stdout, "%sidx\taddr\t\tsize\t\tsection%s\n", GREEN, ENDC);
          while (x != pElf_Header->e_shnum)
          {
            fprintf(stdout, "%s%.2d%s\t", GREEN, x, ENDC);
            fprintf(stdout, "%s0x%.8x\t", RED, pElf32_Shdr->sh_addr);
            fprintf(stdout, "0x%.8x\t%s", pElf32_Shdr->sh_size, ENDC);
            fprintf(stdout, "%s\n", (char *)(ptrNameSection + pElf32_Shdr->sh_name));
            x++;
            pElf32_Shdr++;
          }
          pElf32_Shdr -= x;
          flag_sectheader = 1;
          fprintf(stdout, "\n\n");
        }
      i++;
    }
}
