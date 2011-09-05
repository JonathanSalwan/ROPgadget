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

int main(int argc, char **argv)
{
  unsigned char *data;
  unsigned int size;
  struct stat filestat;

  if (argc == 2 && !strcmp(argv[1], "-v"))
    display_version();
  else if (argc < 3)
    syntax(argv[0]);

  if((stat(argv[2], &filestat)) == -1)
    { perror("stat"); return(-1); }

  size = filestat.st_size;
  data = save_bin_data(argv[2], size);
  pElf_Header = (Elf32_Ehdr *)data;
  pElf32_Shdr = (Elf32_Shdr *)((char *)data + pElf_Header->e_shoff);
  pElf32_Phdr = (Elf32_Phdr *)((char *)data + pElf_Header->e_phoff);

  if (!strcmp(argv[1], "-d"))
    display_data(data, size);
  else if (!strcmp(argv[1], "-g"))
      {
        check_bind_mode(argv);
        search_gadgets(data, size);
      }
  else
    syntax(argv[0]);

  free(data);
  return(0);
}
