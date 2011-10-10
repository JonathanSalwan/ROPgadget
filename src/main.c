/*
** RopGadget - Release v3.2
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** http://shell-storm.org
** 2011-10-10
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

static int check_options(char **argv)
{
  int i;
  struct stat filestat;
  unsigned char *data;
  unsigned int size;

  i = 0;
  while (argv[i] != NULL)
    {
      if (!strcmp(argv[i], "-v"))
        display_version();
      else if (!strcmp(argv[i], "-g"))
        {
          if (argv[i + 1] == NULL)
            syntax(argv[0]);
          pOption.gfile = argv[i + 1];
          if((stat(pOption.gfile, &filestat)) == -1)
            {
              perror("stat");
              exit(EXIT_FAILURE);
            }
          size = filestat.st_size;
          data = save_bin_data(pOption.gfile, size);
          pElf_Header = (Elf32_Ehdr *)data;
          pElf32_Shdr = (Elf32_Shdr *)((char *)data + pElf_Header->e_shoff);
          pElf32_Phdr = (Elf32_Phdr *)((char *)data + pElf_Header->e_phoff);

          check_bind_mode(argv);
          check_filtre_mode(argv);
          check_only_mode(argv);
          check_opcode_mode(argv);
          check_importsc_mode(argv);
          search_gadgets(data, size);
          free(data);
          return (0);
        }
      else if (!strcmp(argv[i], "-d"))
        {
          if (argv[i + 1] == NULL)
            syntax(argv[0]);
          pOption.dfile = argv[i + 1];
          if((stat(pOption.dfile, &filestat)) == -1)
            {
              perror("stat");
              exit(EXIT_FAILURE);
            }
          size = filestat.st_size;
          data = save_bin_data(pOption.dfile, size);
          display_data(data, size);
          free(data);
          return (0);
        }
      i++;
    }
  syntax(argv[0]);
  return (0);
}

int main(__attribute__ ((unused))int argc, char **argv)
{
  check_options(argv);
  return(0);
}
